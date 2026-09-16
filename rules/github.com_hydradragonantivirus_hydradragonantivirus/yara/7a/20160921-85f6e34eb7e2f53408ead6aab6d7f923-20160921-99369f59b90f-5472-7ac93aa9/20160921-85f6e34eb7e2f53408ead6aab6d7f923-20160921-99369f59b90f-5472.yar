rule _20160921_85f6e34eb7e2f53408ead6aab6d7f923_20160921_99369f59b90f_5472 {
  meta:
    description = "datamaliciousorder - from files 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js, 20160921_99369f59b90fb2df18b8570f0403febc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"
    hash2       = "224e0a3dfee910c8afb81d7298f89c0b6e937cbd8062c03cedbe500c3dfe98a2"

  strings:
    $s1 = "0(){return \"MMz\";})(),(function f000(){return \"MKa\";})()];" fullword ascii
    $s2 = "00(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg" ascii
    $s3 = "\"DNa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s4 = "return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})()" ascii
    $s5 = "nction f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}