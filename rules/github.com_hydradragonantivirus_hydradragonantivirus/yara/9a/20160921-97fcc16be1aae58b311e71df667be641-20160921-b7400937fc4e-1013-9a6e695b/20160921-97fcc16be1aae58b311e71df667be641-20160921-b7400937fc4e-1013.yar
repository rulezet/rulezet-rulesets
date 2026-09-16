rule _20160921_97fcc16be1aae58b311e71df667be641_20160921_b7400937fc4e_1013 {
  meta:
    description = "datamaliciousorder - from files 20160921_97fcc16be1aae58b311e71df667be641.js, 20160921_b7400937fc4eb76c7ea3adaa321d7619.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2459214bba37a40478bc984d75c7b1ababcbf0d17eeabe32578555058bdac21f"
    hash2       = "91a8cd111f3381e8f00611988dc7860cfb507d4d297884f9d7d7a01ae96c0fca"

  strings:
    $s1  = "(function f000(){return \"Ot\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){r" ascii
    $s2  = "),(function f000(){return \"Ot\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"TKp\";})(),(function f000()" ascii
    $s3  = "){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KDh\";}" ascii
    $s4  = "(function f000(){return \"DYs\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){r" ascii
    $s5  = "\"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Br\";})(),(funct" ascii
    $s6  = "(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){re" ascii
    $s7  = "on f000(){return \"KDh\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return " ascii
    $s8  = "f000(){return \"ZIi\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Z" ascii
    $s9  = " \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yz\";})(),(func" ascii
    $s10 = "urn \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Qa\";})(),(fu" ascii
    $s11 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"DNa\";" ascii
    $s12 = "Rc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(functio" ascii
    $s13 = "\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Oh\";})(),(function " ascii
    $s14 = "PTs\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s15 = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"DYx\";})(),(f" ascii
    $s16 = "function f000(){return \"IPu\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Lp\";})(),(function f000(){re" ascii
    $s17 = "Gn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yz\";})(),(functio" ascii
    $s18 = "n \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"EZu\";})(),(f" ascii
    $s19 = "urn \"BMj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}