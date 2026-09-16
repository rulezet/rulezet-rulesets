rule _20160921_346ce24842d4c67049d4ae8a4ef57f0b_20160921_4d4f88bcbe1d_2038 {
  meta:
    description = "datamaliciousorder - from files 20160921_346ce24842d4c67049d4ae8a4ef57f0b.js, 20160921_4d4f88bcbe1d7c27849018b54d3401d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24cea6347b33f54d332a2f5000d3f2841a3a09a1270f4da0da530495cac7ac0e"
    hash2       = "8c037da0756f2e03c3daf2ada4f7a359fd0381e67b8eccb57785222e669ac983"

  strings:
    $s1 = "i\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(function" ascii
    $s2 = ";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f00" ascii
    $s3 = ")(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(" ascii
    $s4 = "turn \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(f" ascii
    $s5 = ";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f" ascii
    $s6 = " \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(func" ascii
    $s7 = "00(){return \"Qa\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";" ascii
    $s8 = "})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(function f00" ascii
    $s9 = "ion f000(){return \"RVb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}