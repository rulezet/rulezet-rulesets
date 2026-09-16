rule sig_20161207_0962121483304917dc3058b605ad41e3 {
  meta:
    description = "datamaliciousorder - file 20161207_0962121483304917dc3058b605ad41e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b2c36c2979a6e05f98995a699f17568b493be25e1dd5fabe77f7695d5a70cc8"

  strings:
    $s1 = "var vFs8 = new Function(\"vJXx9\", '{var vMn2 = new Date();vMn2[\"setUTCFullYear\"](\"2003\");if (vMn2.getUTCFullYear().toString" ascii
    $s2 = "var vFs8 = new Function(\"vJXx9\", '{var vMn2 = new Date();vMn2[\"setUTCFullYear\"](\"2003\");if (vMn2.getUTCFullYear().toString" ascii
    $s3 = "var vMb0 = new Function(\"vJXx9\", '{return vJXx9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vJu1 = vJXx9.split(\"###\"); return vJu1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}