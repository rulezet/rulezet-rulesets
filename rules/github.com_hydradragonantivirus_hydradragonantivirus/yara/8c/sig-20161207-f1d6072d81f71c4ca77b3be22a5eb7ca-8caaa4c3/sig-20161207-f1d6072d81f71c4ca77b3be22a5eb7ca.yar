rule sig_20161207_f1d6072d81f71c4ca77b3be22a5eb7ca {
  meta:
    description = "datamaliciousorder - file 20161207_f1d6072d81f71c4ca77b3be22a5eb7ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75a7237ec18dd1b583b11c557b4153594605bd7a15d6ab2fcefdc249db905fde"

  strings:
    $s1 = "var vTTh3 = new Function(\"vGn4\", '{var vJo2 = new Date();vJo2[\"setUTCFullYear\"](\"2003\");if (vJo2.getUTCFullYear().toString" ascii
    $s2 = "var vTTh3 = new Function(\"vGn4\", '{var vJo2 = new Date();vJo2[\"setUTCFullYear\"](\"2003\");if (vJo2.getUTCFullYear().toString" ascii
    $s3 = "var vWc8 = new Function(\"vGn4\", '{return vGn4.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vOo6 = vGn4.split(\"###\"); return vOo6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}