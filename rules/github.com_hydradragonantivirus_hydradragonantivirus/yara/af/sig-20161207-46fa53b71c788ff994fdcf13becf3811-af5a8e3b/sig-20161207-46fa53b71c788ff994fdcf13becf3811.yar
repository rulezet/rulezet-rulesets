rule sig_20161207_46fa53b71c788ff994fdcf13becf3811 {
  meta:
    description = "datamaliciousorder - file 20161207_46fa53b71c788ff994fdcf13becf3811.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d43ea00947214ed8ad10644e74a708bcf244c9590efd5f70a22aafaa59d9f3bf"

  strings:
    $s1 = "var vAe5 = new Function(\"vIw8\", '{var vFg8 = new Date();vFg8[\"setUTCFullYear\"](\"2003\");if (vFg8.getUTCFullYear().toString(" ascii
    $s2 = "var vAe5 = new Function(\"vIw8\", '{var vFg8 = new Date();vFg8[\"setUTCFullYear\"](\"2003\");if (vFg8.getUTCFullYear().toString(" ascii
    $s3 = "var vETr7 = new Function(\"vIw8\", '{return vIw8.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vGTi5 = vIw8.split(\"###\"); return vGTi5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}