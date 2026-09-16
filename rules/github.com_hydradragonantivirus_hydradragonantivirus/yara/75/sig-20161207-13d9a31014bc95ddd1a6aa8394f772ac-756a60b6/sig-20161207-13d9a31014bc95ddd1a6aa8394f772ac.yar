rule sig_20161207_13d9a31014bc95ddd1a6aa8394f772ac {
  meta:
    description = "datamaliciousorder - file 20161207_13d9a31014bc95ddd1a6aa8394f772ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "405e0b94c32095e1c9e2e4e7c49e3476d53af1b31946e89b0cce32348e8bb17e"

  strings:
    $s1 = "var vLv7 = new Function(\"vJf6\", '{var vXBe5 = new Date();vXBe5[\"setUTCFullYear\"](\"2003\");if (vXBe5.getUTCFullYear().toStri" ascii
    $s2 = "var vLv7 = new Function(\"vJf6\", '{var vXBe5 = new Date();vXBe5[\"setUTCFullYear\"](\"2003\");if (vXBe5.getUTCFullYear().toStri" ascii
    $s3 = "var vYx4 = new Function(\"vJf6\", '{return vJf6.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " == \"2003\") {var vKCf9 = vJf6.split(\"###\"); return vKCf9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}