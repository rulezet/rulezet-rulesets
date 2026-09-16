rule sig_20161207_33a612b04de8f8a6acbc9149b62df343 {
  meta:
    description = "datamaliciousorder - file 20161207_33a612b04de8f8a6acbc9149b62df343.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28687256750881f36b73c9b99c985cfbfb47f9ba7794ac61233ce65b8957029f"

  strings:
    $s1 = "new Date();vBHy8[\"setUTCFullYear\"](\"2003\");if (vBHy8.getUTCFullYear().toString(10) == \"2003\") {var vMFb6 = vPz1.split(\"##" ascii
    $s2 = "var vRj5 = new Function(\"vPz1\", '{return vPz1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIt4 = new Function(\"vPz1\"" ascii
    $s3 = "var vRj5 = new Function(\"vPz1\", '{return vPz1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIt4 = new Function(\"vPz1\"" ascii
    $s4 = "eturn vMFb6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}