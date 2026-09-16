rule sig_20161206_d73212f6a911b5048d8ac0b329da300e {
  meta:
    description = "datamaliciousorder - file 20161206_d73212f6a911b5048d8ac0b329da300e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6297534fcb74fb9ee7e028cbd6f00885ed56b1195ea37891385621890da98c83"

  strings:
    $s1 = "var vYc3 = new Function(\"s\", '{var vPPv9 = new Date();vPPv9[\"setUTCFullYear\"](\"2003\");if (vPPv9.getUTCFullYear().toString(" ascii
    $s2 = "var vYc3 = new Function(\"s\", '{var vPPv9 = new Date();vPPv9[\"setUTCFullYear\"](\"2003\");if (vPPv9.getUTCFullYear().toString(" ascii
    $s3 = "function vVYg4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vZq4 = s.split(\"##\"); return vZq4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}