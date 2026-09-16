rule sig_20161208_d1ede251b33b426f1b0c8ddebf047402 {
  meta:
    description = "datamaliciousorder - file 20161208_d1ede251b33b426f1b0c8ddebf047402.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06b9792492a3490073a572c2459d47ee061164d420bab5bed6035e256ca4eb3f"

  strings:
    $s1 = "8 = new Date();vMDc8[\"setUTC\"+\"FullYear\"](\"2003\");if (vMDc8.getUTCFullYear().toString(10) == \"2003\") {var vKRo4 = vISu6." ascii
    $s2 = "var vERd2 = new Function(\"vISu6\", '{return vISu6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQf2 = new Function(\"vIS" ascii
    $s3 = "var vERd2 = new Function(\"vISu6\", '{return vISu6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQf2 = new Function(\"vIS" ascii
    $s4 = "###\"); return vKRo4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}