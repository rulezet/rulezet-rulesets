rule sig_20161207_eb235aff7b93e45757d0cbda298266d1 {
  meta:
    description = "datamaliciousorder - file 20161207_eb235aff7b93e45757d0cbda298266d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0da4ecfa9747ef15d022d402fda72adc886efa8e55da0a89da0b1c49c4fb63c1"

  strings:
    $s1 = "var vLs7 = new Function(\"vBw1\", '{return vBw1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJc3 = new Function(\"vBw1\"" ascii
    $s2 = "ew Date();vYr3[\"setUTCFullYear\"](\"2003\");if (vYr3.getUTCFullYear().toString(10) == \"2003\") {var vKJx5 = vBw1.split(\"####" ascii
    $s3 = "var vLs7 = new Function(\"vBw1\", '{return vBw1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJc3 = new Function(\"vBw1\"" ascii
    $s4 = "rn vKJx5.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}