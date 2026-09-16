rule _20160921_66de660457cd1dcbe458e50b91bafaca_20160921_e949fdc198fe_492 {
  meta:
    description = "datamaliciousorder - from files 20160921_66de660457cd1dcbe458e50b91bafaca.js, 20160921_e949fdc198fee477717395093f5853e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c92eafe23596e161cf04cc6206b7e5cac5dafb3ce36772cc5a8a4f0f827211c"
    hash2       = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"

  strings:
    $s1  = "\"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(func" ascii
    $s2  = "),(function f000(){return \"ZFe\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Qj\";})(),(function f000(){" ascii
    $s3  = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"B" ascii
    $s4  = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";})()" ascii
    $s5  = ";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f00" ascii
    $s6  = "turn \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})()," ascii
    $s7  = "function f000(){return \"Sq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){re" ascii
    $s8  = "0(){return \"PTs\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";" ascii
    $s9  = "),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Br\";})(),(function f000(){" ascii
    $s10 = "00(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Nx\"" ascii
    $s11 = "n\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Yi\";})(),(function " ascii
    $s12 = "on f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return " ascii
    $s13 = "(){return \"PTs\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";" ascii
    $s14 = "ion f000(){return \"MJq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return " ascii
    $s15 = "on f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Wy\";})(),(function f000(){return " ascii
    $s16 = "00(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IPu" ascii
    $s17 = "unction f000(){return \"ZGq\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"MDb\";})(),(function f000(){ret" ascii
    $s18 = "tion f000(){return \"RVb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Uo\";})(),(function f000(){return" ascii
    $s19 = "return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"MJq\";})()" ascii
    $s20 = "ion f000(){return \"MJq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}