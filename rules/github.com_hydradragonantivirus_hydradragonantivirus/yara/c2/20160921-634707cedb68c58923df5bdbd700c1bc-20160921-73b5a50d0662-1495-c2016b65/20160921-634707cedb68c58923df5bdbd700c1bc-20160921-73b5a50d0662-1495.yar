rule _20160921_634707cedb68c58923df5bdbd700c1bc_20160921_73b5a50d0662_1495 {
  meta:
    description = "datamaliciousorder - from files 20160921_634707cedb68c58923df5bdbd700c1bc.js, 20160921_73b5a50d06622b8411077815f2717627.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "152351bec2365a464c735883af22dfe66d59686fad11d1304e9e19accdb6f596"
    hash2       = "ff8a171dec88d707916b1928e49d84c61474fe9b0faf2916e72eadb2b404d04b"

  strings:
    $s1  = "f000(){return \"DIa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"B" ascii
    $s2  = "turn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"RLk\";})()" ascii
    $s3  = "on f000(){return \"Tn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s4  = "),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Iq\";})(),(function f000(){r" ascii
    $s5  = "\"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Yi\";})(),(functi" ascii
    $s6  = "\"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"NYh\";})(),(fun" ascii
    $s7  = "n f000(){return \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s8  = ")(),(function f000(){return \"BQb\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s9  = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"K" ascii
    $s10 = "urn \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s11 = "rn \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"BQb\";})(),(f" ascii
    $s12 = "function f000(){return \"DYx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){r" ascii
    $s13 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Mc\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}