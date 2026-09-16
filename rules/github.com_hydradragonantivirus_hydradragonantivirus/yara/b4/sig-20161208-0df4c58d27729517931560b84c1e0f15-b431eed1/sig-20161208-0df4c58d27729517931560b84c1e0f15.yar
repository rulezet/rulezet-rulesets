rule sig_20161208_0df4c58d27729517931560b84c1e0f15 {
  meta:
    description = "datamaliciousorder - file 20161208_0df4c58d27729517931560b84c1e0f15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e6c578f02da71cc84b4e1b4ba68855ebc41efca241c2c1e46d8c31129276ad0"

  strings:
    $s1 = "var vNk5 = new Function(\"vBZy9\", '{return vBZy9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCt5 = new Function(\"vBZy" ascii
    $s2 = " = new Date();vKOu4[\"setUTC\"+\"FullYear\"](\"2003\");if (vKOu4.getUTCFullYear().toString(10) == \"2003\") {var vICk2 = vBZy9.s" ascii
    $s3 = "var vNk5 = new Function(\"vBZy9\", '{return vBZy9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCt5 = new Function(\"vBZy" ascii
    $s4 = "##\"); return vICk2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}