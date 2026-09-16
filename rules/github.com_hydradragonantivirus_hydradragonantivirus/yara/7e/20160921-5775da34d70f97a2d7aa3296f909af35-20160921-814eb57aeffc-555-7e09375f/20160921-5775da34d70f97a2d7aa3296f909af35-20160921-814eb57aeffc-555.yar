rule _20160921_5775da34d70f97a2d7aa3296f909af35_20160921_814eb57aeffc_555 {
  meta:
    description = "datamaliciousorder - from files 20160921_5775da34d70f97a2d7aa3296f909af35.js, 20160921_814eb57aeffc75442964829345cc9f96.js, 20160921_89a260f4d6da4d97f251f843cf5e94b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "270e1d840937d10ac3eb1fdd04f0fbbbfd31a88a2f316c94c5167a23a2940644"
    hash2       = "2736df4d651a33824aba7abffa7c08414414ffed9f5f27b4b2d81101cfeb7117"
    hash3       = "700f6c802eb024896efe2b22255973b53752a8f129213c9bba2c4f2ebdc53988"

  strings:
    $s1  = "eturn \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})()" ascii
    $s2  = "nction f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DNa\";})(),(function f000(){retu" ascii
    $s3  = "),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MBb\";})(),(function f000(" ascii
    $s4  = "v\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s5  = "on f000(){return \"DAp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s6  = ";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f" ascii
    $s7  = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){retu" ascii
    $s8  = "\"Nv\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s9  = "GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Wy\";})(),(function" ascii
    $s10 = "00(){return \"SEo\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn" ascii
    $s11 = "\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"WIj\";})(),(function f" ascii
    $s12 = "{return \"UEg\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(" ascii
    $s13 = "tion f000(){return \"ZGq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s14 = "function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){ret" ascii
    $s15 = "Db\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Sv\";})(),(function" ascii
    $s16 = "{return \"GGn\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Yz\";})(" ascii
    $s17 = "turn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MJq\";})()," ascii
    $s18 = "0(){return \"XTn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"OMd\";" ascii
    $s19 = "00(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Tb" ascii
    $s20 = " \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wb\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}