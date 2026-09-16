rule sig_20161207_b0ff38575efdfe1398752cb0ba2db0d0 {
  meta:
    description = "datamaliciousorder - file 20161207_b0ff38575efdfe1398752cb0ba2db0d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "690e337afd83a8aa6b64de4e5261bd774f80b414c956808d00dc783d01233ba1"

  strings:
    $s1 = "var vMw5 = new Function(\"vDTz3\", '{var vSn5 = new Date();vSn5[\"setUTCFullYear\"](\"2003\");if (vSn5.getUTCFullYear().toString" ascii
    $s2 = "var vMw5 = new Function(\"vDTz3\", '{var vSn5 = new Date();vSn5[\"setUTCFullYear\"](\"2003\");if (vSn5.getUTCFullYear().toString" ascii
    $s3 = "var vNi8 = new Function(\"vDTz3\", '{return vDTz3.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vYd5 = vDTz3.split(\"###\"); return vYd5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}