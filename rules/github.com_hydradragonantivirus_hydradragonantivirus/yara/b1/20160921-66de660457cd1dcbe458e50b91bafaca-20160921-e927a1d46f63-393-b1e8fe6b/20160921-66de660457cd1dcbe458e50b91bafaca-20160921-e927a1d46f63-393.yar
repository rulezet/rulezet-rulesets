rule _20160921_66de660457cd1dcbe458e50b91bafaca_20160921_e927a1d46f63_393 {
  meta:
    description = "datamaliciousorder - from files 20160921_66de660457cd1dcbe458e50b91bafaca.js, 20160921_e927a1d46f63fcc6ccb740b1d71293f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c92eafe23596e161cf04cc6206b7e5cac5dafb3ce36772cc5a8a4f0f827211c"
    hash2       = "a681cf04685052da0d288a0246e49880f34a91dc46ff378f7cf1859ae526c1ef"

  strings:
    $s1  = "n f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TK" ascii
    $s2  = "nction f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){retur" ascii
    $s3  = "0(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\"" ascii
    $s4  = "eturn \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})()," ascii
    $s5  = "ction f000(){return \"WIj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(function f000(){retur" ascii
    $s6  = "rn \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTs\";})(),(f" ascii
    $s7  = "function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){ret" ascii
    $s8  = ")(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(" ascii
    $s9  = "return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})()" ascii
    $s10 = " f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc" ascii
    $s11 = "(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000()" ascii
    $s12 = "{return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})" ascii
    $s13 = "rn \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fun" ascii
    $s14 = "00(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Do\";" ascii
    $s15 = "n \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(fu" ascii
    $s16 = "n f000(){return \"BIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s17 = "turn \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s18 = "){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})" ascii
    $s19 = "(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){ret" ascii
    $s20 = "unction f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}