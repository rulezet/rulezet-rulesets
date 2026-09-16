rule _20160921_16200453422b5793a6a93d4bb423b0ea_20160921_3bce2f31e98c_1540 {
  meta:
    description = "datamaliciousorder - from files 20160921_16200453422b5793a6a93d4bb423b0ea.js, 20160921_3bce2f31e98c152d025886ed17309773.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d968eb9bb2807e5889794bf130036c2c81716cd0166eed67a45c9ef3f81607c3"
    hash2       = "9a668f4a1c8cd764f3d7afa71030b8b37f7ec8d0b0b42b9a93aa82346b5ae616"

  strings:
    $s1  = "unction f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(function f000(){retur" ascii
    $s2  = "n \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s3  = "0(){return \"Vj\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";" ascii
    $s4  = "f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Q" ascii
    $s5  = "urn \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s6  = "n f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"O" ascii
    $s7  = "b\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s8  = "eturn \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})()" ascii
    $s9  = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){retu" ascii
    $s10 = "\"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"TKp\";})(),(func" ascii
    $s11 = "f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"K" ascii
    $s12 = "unction f000(){return \"KDh\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"MJq\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}