rule _20160921_09b25bffbd6bee308b23db7ad035cfd2_20160921_10a3e0605b8c_4317 {
  meta:
    description = "datamaliciousorder - from files 20160921_09b25bffbd6bee308b23db7ad035cfd2.js, 20160921_10a3e0605b8ced0a0dee77069aa99014.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0646df8d41668a96251f0443ca802dda915eadd4bc1fdb29b89948f4eb238893"
    hash2       = "462b92b513dfa104fe3c095cbf98c34389b13ed004671baf4f95430e8487a108"

  strings:
    $s1 = "function f000(){return \"NYh\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"OMd\";})(),(function f000(){re" ascii
    $s2 = "\"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DYx\";})(),(funct" ascii
    $s3 = "000(){return \"Go\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj" ascii
    $s4 = "(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000" ascii
    $s5 = "000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}