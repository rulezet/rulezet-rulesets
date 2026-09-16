rule _20160921_13c992e435ed245b1977cea0df2db815_20160921_cae1392fd0c6_4448 {
  meta:
    description = "datamaliciousorder - from files 20160921_13c992e435ed245b1977cea0df2db815.js, 20160921_cae1392fd0c6da8c370b46e3e8040401.js, 20160921_e83251070761df6a7fe56a790f4a7a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"
    hash2       = "f67c8d099609c97880a9ea12beb3c83faaf2411bf12032595ad5baa45d985a04"
    hash3       = "0ca0db55a551923b328ba28035ed857a5c51dfd4c6e1060bd34ab4bc3d27b75f"

  strings:
    $s1 = "eturn \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})()," ascii
    $s2 = "eturn \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"OMd\";})()," ascii
    $s3 = "n f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"" ascii
    $s4 = "(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";" ascii
    $s5 = " \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Qa\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}