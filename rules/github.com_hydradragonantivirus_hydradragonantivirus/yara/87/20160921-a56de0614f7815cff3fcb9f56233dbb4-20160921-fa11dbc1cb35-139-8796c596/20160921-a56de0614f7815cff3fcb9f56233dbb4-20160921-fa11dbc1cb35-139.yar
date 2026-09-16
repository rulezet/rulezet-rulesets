rule _20160921_a56de0614f7815cff3fcb9f56233dbb4_20160921_fa11dbc1cb35_139 {
  meta:
    description = "datamaliciousorder - from files 20160921_a56de0614f7815cff3fcb9f56233dbb4.js, 20160921_fa11dbc1cb358c8446ac1ba033c8a4c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa71b33b4ef1bf0fefff91c2876915e8ca80c82d473862703c383c6da0ad0186"
    hash2       = "27a60061641d8c44f2b882fcd06e72ca5721eaecb40ea10ad0b87c0c5f3c236f"

  strings:
    $s1  = "unction f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Nv\";})(),(function f000(){ret" ascii
    $s2  = "urn \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"NYh\";})(),(" ascii
    $s3  = "turn \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(" ascii
    $s4  = "ction f000(){return \"Nv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return" ascii
    $s5  = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NYh\";})()," ascii
    $s6  = "rn \"Oh\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(f" ascii
    $s7  = "n\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Mt\";})(),(function " ascii
    $s8  = "ction f000(){return \"Mt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s9  = "){return \"MDb\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Rh\";})" ascii
    $s10 = "n \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(func" ascii
    $s11 = "),(function f000(){return \"Vj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"MDb\";})(),(function f000()" ascii
    $s12 = "\"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(functi" ascii
    $s13 = "\"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(func" ascii
    $s14 = "function f000(){return \"EZu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Tn\";})(),(function f000(){ret" ascii
    $s15 = "(),(function f000(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000" ascii
    $s16 = "f000(){return \"IAa\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MD" ascii
    $s17 = "urn \"OUx\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TKl\";})()," ascii
    $s18 = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){retur" ascii
    $s19 = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"BMj" ascii
    $s20 = "\"Br\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}