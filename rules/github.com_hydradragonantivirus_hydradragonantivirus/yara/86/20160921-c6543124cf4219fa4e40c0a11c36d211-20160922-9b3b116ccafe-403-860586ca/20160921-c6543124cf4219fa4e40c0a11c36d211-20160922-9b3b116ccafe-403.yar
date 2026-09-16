rule _20160921_c6543124cf4219fa4e40c0a11c36d211_20160922_9b3b116ccafe_403 {
  meta:
    description = "datamaliciousorder - from files 20160921_c6543124cf4219fa4e40c0a11c36d211.js, 20160922_9b3b116ccafe79961f3e5b8baaf2ade1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e6e6772ef9133726c2b17ebda7c01433c0b60252b2e9446e3c8a2e6595d981c"
    hash2       = "3e53e6ba6e3163cbf17f110b2b7e3a79966fc578ec4ae1ed2de13f0fac0de834"

  strings:
    $s1  = "{return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Br\";})()" ascii
    $s2  = "00(){return \"PTs\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s3  = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"KDh\";})(),(fu" ascii
    $s4  = "000(){return \"Nx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Br" ascii
    $s5  = "ion f000(){return \"ZFe\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s6  = "\"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mt\";})(),(func" ascii
    $s7  = "),(function f000(){return \"Wh\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Yz\";})(),(function f000(){" ascii
    $s8  = "unction f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Qa\";})(),(function f000(){retu" ascii
    $s9  = ",(function f000(){return \"DYs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s10 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DYx\";})(),(function f00" ascii
    $s11 = "on f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return " ascii
    $s12 = " f000(){return \"Um\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"MD" ascii
    $s13 = "(function f000(){return \"EZu\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Br\";})(),(function f000(){r" ascii
    $s14 = "eturn \"PTs\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})()" ascii
    $s15 = "tion f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Nx\";})(),(function f000(){return" ascii
    $s16 = "n \"ZGq\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s17 = "unction f000(){return \"RVb\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Br\";})(),(function f000(){ret" ascii
    $s18 = "00(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Nx\"" ascii
    $s19 = "return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"SGs\";})()" ascii
    $s20 = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Go\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}