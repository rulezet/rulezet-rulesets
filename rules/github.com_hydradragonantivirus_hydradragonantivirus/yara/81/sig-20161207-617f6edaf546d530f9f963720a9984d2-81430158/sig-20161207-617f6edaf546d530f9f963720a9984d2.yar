rule sig_20161207_617f6edaf546d530f9f963720a9984d2 {
  meta:
    description = "datamaliciousorder - file 20161207_617f6edaf546d530f9f963720a9984d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19ea223550db6e338f7069600db1c0b290e45724c78bc3b67b87f43aaafee4c3"

  strings:
    $s1 = "var vAJe1 = new Function(\"vUw8\", '{var vRPv0 = new Date();vRPv0[\"setUTCFullYear\"](\"2003\");if (vRPv0.getUTCFullYear().toStr" ascii
    $s2 = "var vAJe1 = new Function(\"vUw8\", '{var vRPv0 = new Date();vRPv0[\"setUTCFullYear\"](\"2003\");if (vRPv0.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vWYa3 = vUw8.split(\"###\"); return vWYa3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vGs8 = new Function(\"vUw8\", '{return vUw8.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}