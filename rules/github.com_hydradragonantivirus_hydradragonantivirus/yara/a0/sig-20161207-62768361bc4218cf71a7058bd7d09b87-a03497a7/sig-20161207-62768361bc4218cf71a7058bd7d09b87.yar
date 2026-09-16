rule sig_20161207_62768361bc4218cf71a7058bd7d09b87 {
  meta:
    description = "datamaliciousorder - file 20161207_62768361bc4218cf71a7058bd7d09b87.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b71e7af459ff9b4463b07af3a4b94f9045f7a7d1eda05cf976a6118e8252d16d"

  strings:
    $s1 = "var vJSn6 = new Function(\"vUBi9\", '{var vWc8 = new Date();vWc8[\"setUTCFullYear\"](\"2003\");if (vWc8.getUTCFullYear().toStrin" ascii
    $s2 = "var vJSn6 = new Function(\"vUBi9\", '{var vWc8 = new Date();vWc8[\"setUTCFullYear\"](\"2003\");if (vWc8.getUTCFullYear().toStrin" ascii
    $s3 = "var vZs9 = new Function(\"vUBi9\", '{return vUBi9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "== \"2003\") {var vLj8 = vUBi9.split(\"###\"); return vLj8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}