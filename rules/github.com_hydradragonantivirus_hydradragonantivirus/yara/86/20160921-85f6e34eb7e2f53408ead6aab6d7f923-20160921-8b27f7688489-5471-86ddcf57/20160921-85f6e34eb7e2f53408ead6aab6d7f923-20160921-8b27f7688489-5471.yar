rule _20160921_85f6e34eb7e2f53408ead6aab6d7f923_20160921_8b27f7688489_5471 {
  meta:
    description = "datamaliciousorder - from files 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js, 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"
    hash2       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash3       = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"

  strings:
    $s1 = "c\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function " ascii
    $s2 = "ion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s3 = "x\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s4 = ")(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(" ascii
    $s5 = "Pt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}