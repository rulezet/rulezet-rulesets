rule _20160921_8471da3d602dedb9a4749d6e2c757b47_20160921_99369f59b90f_5463 {
  meta:
    description = "datamaliciousorder - from files 20160921_8471da3d602dedb9a4749d6e2c757b47.js, 20160921_99369f59b90fb2df18b8570f0403febc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"
    hash2       = "224e0a3dfee910c8afb81d7298f89c0b6e937cbd8062c03cedbe500c3dfe98a2"

  strings:
    $s1 = "{return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"IPu\";})" ascii
    $s2 = "ion f000(){return \"DAp\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii
    $s3 = ")(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s4 = "(){return \"IAa\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";}" ascii
    $s5 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}