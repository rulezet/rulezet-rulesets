rule sig_20161207_2dd069a9eb4d05560bb5eecc64fd9a21 {
  meta:
    description = "datamaliciousorder - file 20161207_2dd069a9eb4d05560bb5eecc64fd9a21.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a24fb31b7d0cd9670d4a9f7882f9550f31f7b286fed1b1d5fc49c6851117a2dc"

  strings:
    $s1 = "var vAJs0 = new Function(\"vYCr3\", '{var vEAc3 = new Date();vEAc3[\"setUTCFullYear\"](\"2003\");if (vEAc3.getUTCFullYear().toSt" ascii
    $s2 = "var vAJs0 = new Function(\"vYCr3\", '{var vEAc3 = new Date();vEAc3[\"setUTCFullYear\"](\"2003\");if (vEAc3.getUTCFullYear().toSt" ascii
    $s3 = "0) == \"2003\") {var vDv0 = vYCr3.split(\"###\"); return vDv0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vCIo9 = new Function(\"vYCr3\", '{return vYCr3.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}