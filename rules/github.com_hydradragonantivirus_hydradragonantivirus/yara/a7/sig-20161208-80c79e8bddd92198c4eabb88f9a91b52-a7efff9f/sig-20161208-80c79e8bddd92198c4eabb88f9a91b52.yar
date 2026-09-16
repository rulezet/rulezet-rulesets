rule sig_20161208_80c79e8bddd92198c4eabb88f9a91b52 {
  meta:
    description = "datamaliciousorder - file 20161208_80c79e8bddd92198c4eabb88f9a91b52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08d07afe3ab22791ee96a626b3b88ec868dda6e9a5ac03db294c6950e5a74bb6"

  strings:
    $s1 = " new Date();vKPb4[\"setUTC\"+\"FullYear\"](\"2003\");if (vKPb4.getUTCFullYear().toString(10) == \"2003\") {var vKi0 = vIe5.split" ascii
    $s2 = "var vTBq3 = new Function(\"vIe5\", '{return vIe5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQy7 = new Function(\"vIe5" ascii
    $s3 = "var vTBq3 = new Function(\"vIe5\", '{return vIe5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQy7 = new Function(\"vIe5" ascii
    $s4 = "; return vKi0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}