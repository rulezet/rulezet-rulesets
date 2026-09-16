rule _20160921_033cb159a63153428b22d38108b692e4_20160921_42c93aee0243_1527 {
  meta:
    description = "datamaliciousorder - from files 20160921_033cb159a63153428b22d38108b692e4.js, 20160921_42c93aee0243f217ab1a00a402ced889.js, 20160921_b2c7637ff56cbf278f1a457ae1833df9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d370303fc83ddc3470e00cb54841641f9f338c2f025096e84d40782778041a8b"
    hash2       = "740dfd31653bea8abfef6b3038aec0b854878d45a8de4bde67cdb9124c6bbea0"
    hash3       = "a19789bb6f28d27bc82c039f4db69fb5cc4c189a7a47cddfffcdc6eace37a408"

  strings:
    $s1  = "function f000(){return \"Wb\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"IAa\";})(),(function f000(){re" ascii
    $s2  = "n\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s3  = " f000(){return \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IA" ascii
    $s4  = "Ux\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(functio" ascii
    $s5  = "n f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s6  = "(function f000(){return \"Go\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){re" ascii
    $s7  = "(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Qa\";})(),(function f000()" ascii
    $s8  = "00(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\"" ascii
    $s9  = "turn \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(" ascii
    $s10 = "n\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Nv\";})(),(function" ascii
    $s11 = "eturn \"HJm\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DIa\";})()," ascii
    $s12 = "n \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}