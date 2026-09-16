rule sig_20161206_b8d15a629035f07f729cb041d61c6c3a {
  meta:
    description = "datamaliciousorder - file 20161206_b8d15a629035f07f729cb041d61c6c3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f976028716bb3bd74a3629dca3908bbebf4fd8f60aa15f7a74aef9ff68dd9fa0"

  strings:
    $s1 = "var vMm5 = new Function(\"s\", '{var vTGc0 = new Date();vTGc0[\"setUTCFullYear\"](\"2003\");if (vTGc0.getUTCFullYear().toString(" ascii
    $s2 = "var vMm5 = new Function(\"s\", '{var vTGc0 = new Date();vTGc0[\"setUTCFullYear\"](\"2003\");if (vTGc0.getUTCFullYear().toString(" ascii
    $s3 = "function vXAd5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vQd2 = s.split(\"##\"); return vQd2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}