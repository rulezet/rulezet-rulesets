rule sig_20161207_8f5bb844c67c8261dbf27e81c2edc19e {
  meta:
    description = "datamaliciousorder - file 20161207_8f5bb844c67c8261dbf27e81c2edc19e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f179c56857d8ef356595cccfb150d66be39d4a8e57169e8b7245b751ba641ab"

  strings:
    $s1 = "var vYWn8 = new Function(\"vWy4\", '{var vRe1 = new Date();vRe1[\"setUTCFullYear\"](\"2003\");if (vRe1.getUTCFullYear().toString" ascii
    $s2 = "var vYWn8 = new Function(\"vWy4\", '{var vRe1 = new Date();vRe1[\"setUTCFullYear\"](\"2003\");if (vRe1.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vDj5 = vWy4.split(\"###\"); return vDj5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vPCt4 = new Function(\"vWy4\", '{return vWy4.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}