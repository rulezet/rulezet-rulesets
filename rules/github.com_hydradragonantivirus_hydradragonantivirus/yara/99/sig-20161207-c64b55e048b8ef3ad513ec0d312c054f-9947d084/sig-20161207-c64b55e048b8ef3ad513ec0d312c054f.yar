rule sig_20161207_c64b55e048b8ef3ad513ec0d312c054f {
  meta:
    description = "datamaliciousorder - file 20161207_c64b55e048b8ef3ad513ec0d312c054f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3c74a6150fba4aa63587feadb97baca43be2284bb0de39de9c50e7f1cdac57e"

  strings:
    $s1 = "var vPXv5 = new Function(\"vBb8\", '{var vWf2 = new Date();vWf2[\"setUTCFullYear\"](\"2003\");if (vWf2.getUTCFullYear().toString" ascii
    $s2 = "var vPXv5 = new Function(\"vBb8\", '{var vWf2 = new Date();vWf2[\"setUTCFullYear\"](\"2003\");if (vWf2.getUTCFullYear().toString" ascii
    $s3 = "var vKl1 = new Function(\"vBb8\", '{return vBb8.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vNSr1 = vBb8.split(\"###\"); return vNSr1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}