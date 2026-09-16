rule sig_20161206_a03d3703d7fb7941ce24979d736a0087 {
  meta:
    description = "datamaliciousorder - file 20161206_a03d3703d7fb7941ce24979d736a0087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d6025b6ace88fee8dbdf60fcd302927fdd61df65fd22bd90bac717a02d78fe3"

  strings:
    $s1 = "var vOBm0 = new Function(\"s\", '{var vAu1 = new Date();vAu1[\"setUTCFullYear\"](\"2003\");if (vAu1.getUTCFullYear().toString(10" ascii
    $s2 = "var vOBm0 = new Function(\"s\", '{var vAu1 = new Date();vAu1[\"setUTCFullYear\"](\"2003\");if (vAu1.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vUk1 = s.split(\"##\"); return vUk1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vKb4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}