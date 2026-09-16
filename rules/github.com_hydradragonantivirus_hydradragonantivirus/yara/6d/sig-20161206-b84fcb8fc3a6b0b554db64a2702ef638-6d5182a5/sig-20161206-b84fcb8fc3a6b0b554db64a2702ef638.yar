rule sig_20161206_b84fcb8fc3a6b0b554db64a2702ef638 {
  meta:
    description = "datamaliciousorder - file 20161206_b84fcb8fc3a6b0b554db64a2702ef638.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5877c02d5078fa6e5474874ca1520db41e87c9bb8d122e34085de0a326d54285"

  strings:
    $s1 = "var vAVx9 = new Function(\"s\", '{var vZJb7 = new Date();vZJb7[\"setUTCFullYear\"](\"2003\");if (vZJb7.getUTCFullYear().toString" ascii
    $s2 = "var vAVx9 = new Function(\"s\", '{var vZJb7 = new Date();vZJb7[\"setUTCFullYear\"](\"2003\");if (vZJb7.getUTCFullYear().toString" ascii
    $s3 = "function vHVa2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vRDq3 = s.split(\"##\"); return vRDq3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}