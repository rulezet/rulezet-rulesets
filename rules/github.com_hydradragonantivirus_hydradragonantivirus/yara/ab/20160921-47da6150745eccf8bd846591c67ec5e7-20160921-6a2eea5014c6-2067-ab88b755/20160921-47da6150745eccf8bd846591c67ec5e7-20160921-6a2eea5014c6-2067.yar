rule _20160921_47da6150745eccf8bd846591c67ec5e7_20160921_6a2eea5014c6_2067 {
  meta:
    description = "datamaliciousorder - from files 20160921_47da6150745eccf8bd846591c67ec5e7.js, 20160921_6a2eea5014c6e10514154c4a8ee7c1be.js, 20160921_814eb57aeffc75442964829345cc9f96.js, 20160921_89a260f4d6da4d97f251f843cf5e94b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a6547815adb02f36991578330e4cb005f8225b3a8e4c85d5e2c5907a22e325c"
    hash2       = "b1fa490690ec2cf24ba4236d1fa675827bce812ac4cd92a59a9b5261b979f8a3"
    hash3       = "2736df4d651a33824aba7abffa7c08414414ffed9f5f27b4b2d81101cfeb7117"
    hash4       = "700f6c802eb024896efe2b22255973b53752a8f129213c9bba2c4f2ebdc53988"

  strings:
    $s1 = "Db\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Um\";})(),(function" ascii
    $s2 = "turn \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})()," ascii
    $s3 = "function f000(){return \"DNa\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"MDb\";})(),(function f000(){re" ascii
    $s4 = "\"PTs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(funct" ascii
    $s5 = "MBb\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Vj\";})(),(functio" ascii
    $s6 = "n \"KDh\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s7 = "{return \"Sq\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})()" ascii
    $s8 = "000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Kw" ascii
    $s9 = "n f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}