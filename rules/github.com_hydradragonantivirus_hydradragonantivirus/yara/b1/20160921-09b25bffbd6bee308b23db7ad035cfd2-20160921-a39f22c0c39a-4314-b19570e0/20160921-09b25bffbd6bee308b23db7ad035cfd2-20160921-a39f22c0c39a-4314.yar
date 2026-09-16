rule _20160921_09b25bffbd6bee308b23db7ad035cfd2_20160921_a39f22c0c39a_4314 {
  meta:
    description = "datamaliciousorder - from files 20160921_09b25bffbd6bee308b23db7ad035cfd2.js, 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0646df8d41668a96251f0443ca802dda915eadd4bc1fdb29b89948f4eb238893"
    hash2       = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"

  strings:
    $s1 = "unction f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){ret" ascii
    $s2 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){retu" ascii
    $s3 = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"" ascii
    $s4 = "TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(funct" ascii
    $s5 = "{return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}