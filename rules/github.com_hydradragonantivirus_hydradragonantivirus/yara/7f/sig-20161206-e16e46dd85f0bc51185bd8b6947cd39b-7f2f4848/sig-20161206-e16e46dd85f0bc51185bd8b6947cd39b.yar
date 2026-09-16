rule sig_20161206_e16e46dd85f0bc51185bd8b6947cd39b {
  meta:
    description = "datamaliciousorder - file 20161206_e16e46dd85f0bc51185bd8b6947cd39b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6206d54c8c2b1a17cbbd23cac4229201835b712032ea1e9d3a8e9de9704c9de"

  strings:
    $s1 = "var vGGn3 = new Function(\"s\", '{var vMs1 = new Date();vMs1[\"setUTCFullYear\"](\"2003\");if (vMs1.getUTCFullYear().toString(10" ascii
    $s2 = "var vGGn3 = new Function(\"s\", '{var vMs1 = new Date();vMs1[\"setUTCFullYear\"](\"2003\");if (vMs1.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vFc6 = s.split(\"##\"); return vFc6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vSBn4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}