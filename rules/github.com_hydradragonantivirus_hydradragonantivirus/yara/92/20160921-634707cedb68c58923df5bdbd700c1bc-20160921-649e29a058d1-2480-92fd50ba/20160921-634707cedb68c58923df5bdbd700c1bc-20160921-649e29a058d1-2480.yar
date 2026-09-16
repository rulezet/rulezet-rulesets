rule _20160921_634707cedb68c58923df5bdbd700c1bc_20160921_649e29a058d1_2480 {
  meta:
    description = "datamaliciousorder - from files 20160921_634707cedb68c58923df5bdbd700c1bc.js, 20160921_649e29a058d10c3bf9a5a5a06eb3b603.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "152351bec2365a464c735883af22dfe66d59686fad11d1304e9e19accdb6f596"
    hash2       = "6565dca0eb9e0e467a96242f29a80c650cc40a8892572ce8c28bfd197ace7fd0"

  strings:
    $s1 = "})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Qa\";})(),(function f000(" ascii
    $s2 = "\"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Vu\";})(),(func" ascii
    $s3 = "ction f000(){return \"ZFe\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return" ascii
    $s4 = "000(){return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KDh" ascii
    $s5 = "GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"NYh\";})(),(funct" ascii
    $s6 = " \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"EZu\";})(),(fu" ascii
    $s7 = "function f000(){return \"RLk\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s8 = "rn \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Oe\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}