rule sig_20161207_78f5f84385feea2e18b8bb6f4a6ce748 {
  meta:
    description = "datamaliciousorder - file 20161207_78f5f84385feea2e18b8bb6f4a6ce748.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "200edc7075b3d69a797cafb80b8373a6c87b02a71ebfb998d135b648caf4bf50"

  strings:
    $s1 = "8 = new Date();vSAz8[\"setUTCFullYear\"](\"2003\");if (vSAz8.getUTCFullYear().toString(10) == \"2003\") {var vSa4 = vGAl9.split(" ascii
    $s2 = "var vNWu6 = new Function(\"vGAl9\", '{return vGAl9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPa1 = new Function(\"vGA" ascii
    $s3 = "var vNWu6 = new Function(\"vGAl9\", '{return vGAl9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPa1 = new Function(\"vGA" ascii
    $s4 = "); return vSa4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}