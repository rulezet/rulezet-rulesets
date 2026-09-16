rule sig_20161207_4fae70c37d6f8a2785a8bcc2a3fce341 {
  meta:
    description = "datamaliciousorder - file 20161207_4fae70c37d6f8a2785a8bcc2a3fce341.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "075889b7d0e8132dbbe79bdb7b3c1e65aeedf4a8b4bc873146f4734678413468"

  strings:
    $s1 = "var vHb7 = new Function(\"vSKc5\", '{var vXMj3 = new Date();vXMj3[\"setUTCFullYear\"](\"2003\");if (vXMj3.getUTCFullYear().toStr" ascii
    $s2 = "var vHb7 = new Function(\"vSKc5\", '{var vXMj3 = new Date();vXMj3[\"setUTCFullYear\"](\"2003\");if (vXMj3.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vPIj1 = vSKc5.split(\"###\"); return vPIj1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vAe9 = new Function(\"vSKc5\", '{return vSKc5.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}