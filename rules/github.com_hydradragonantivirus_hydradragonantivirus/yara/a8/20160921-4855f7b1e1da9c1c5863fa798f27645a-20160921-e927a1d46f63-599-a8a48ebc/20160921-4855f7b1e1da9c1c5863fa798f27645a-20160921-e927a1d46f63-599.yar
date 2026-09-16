rule _20160921_4855f7b1e1da9c1c5863fa798f27645a_20160921_e927a1d46f63_599 {
  meta:
    description = "datamaliciousorder - from files 20160921_4855f7b1e1da9c1c5863fa798f27645a.js, 20160921_e927a1d46f63fcc6ccb740b1d71293f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c9b29105af371fead56301baf1fdec90bfe0a8b339dbda43258a67443183fcc"
    hash2       = "a681cf04685052da0d288a0246e49880f34a91dc46ff378f7cf1859ae526c1ef"

  strings:
    $s1  = "return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Kw\";})()," ascii
    $s2  = "n \"PTs\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"OMd\";})(),(fu" ascii
    $s3  = " \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s4  = "0(){return \"ZIi\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";" ascii
    $s5  = "tion f000(){return \"Qa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii
    $s6  = "00(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Kw\";" ascii
    $s7  = "on f000(){return \"Sv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"NBs\";})(),(function f000(){return " ascii
    $s8  = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"MBb\";})" ascii
    $s9  = ";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f" ascii
    $s10 = "Db\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"RVb\";})(),(functio" ascii
    $s11 = "){return \"DYs\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";" ascii
    $s12 = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Qa\"" ascii
    $s13 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){retur" ascii
    $s14 = "00(){return \"KDh\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb" ascii
    $s15 = "on f000(){return \"PTs\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return " ascii
    $s16 = "ction f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"UEg\";})(),(function f000(){retu" ascii
    $s17 = "n f000(){return \"Tb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"G" ascii
    $s18 = "ion f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s19 = ";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Wy\";})(),(function f00" ascii
    $s20 = "\"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}