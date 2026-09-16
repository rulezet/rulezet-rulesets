rule _20160921_b2002e7f99c6e0351a90c5fe98b8b775_20160921_ff1932b6e914_1747 {
  meta:
    description = "datamaliciousorder - from files 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js, 20160921_ff1932b6e91481dd80ff6251296b57fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"
    hash2       = "07e5271d8517f89575dc2737fae5e8da89c7f2f25cd40c68e183d826da6b2bf0"

  strings:
    $s1  = "0(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn" ascii
    $s2  = "00(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Km\";" ascii
    $s3  = "return \"MKa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Tn\";})()" ascii
    $s4  = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Sv\";})(),(function f00" ascii
    $s5  = "turn \"SGs\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()" ascii
    $s6  = "n \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"TKp\";})(),(fun" ascii
    $s7  = "eturn \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"MJq\";})()" ascii
    $s8  = "(),(function f000(){return \"BMj\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s9  = "on f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Uo\";})(),(function f000(){return " ascii
    $s10 = "return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(" ascii
    $s11 = "tion f000(){return \"PTi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Qa\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}