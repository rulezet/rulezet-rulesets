rule _20160921_47da6150745eccf8bd846591c67ec5e7_20160921_6a2eea5014c6_6 {
  meta:
    description = "datamaliciousorder - from files 20160921_47da6150745eccf8bd846591c67ec5e7.js, 20160921_6a2eea5014c6e10514154c4a8ee7c1be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a6547815adb02f36991578330e4cb005f8225b3a8e4c85d5e2c5907a22e325c"
    hash2       = "b1fa490690ec2cf24ba4236d1fa675827bce812ac4cd92a59a9b5261b979f8a3"

  strings:
    $s1  = "n \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yi\";})(),(func" ascii
    $s2  = "rn \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Sq\";})(),(fu" ascii
    $s3  = "f000(){return \"Mu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\"" ascii
    $s4  = "rn \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s5  = "function f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Sj\";})(),(function f000(){re" ascii
    $s6  = "(function f000(){return \"Qj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"OMd\";})(),(function f000(){re" ascii
    $s7  = "urn \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(f" ascii
    $s8  = "f000(){return \"Um\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"TKl" ascii
    $s9  = "nction f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vj\";})(),(function f000(){retur" ascii
    $s10 = "unction f000(){return \"MMz\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"KXg\";})(),(function f000(){re" ascii
    $s11 = "eturn \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})()," ascii
    $s12 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Sq\";})(),(function f000(){r" ascii
    $s13 = "00(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";" ascii
    $s14 = "n \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"UEg\";})(),(f" ascii
    $s15 = " \"Qz\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(funct" ascii
    $s16 = "000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Qj\"" ascii
    $s17 = "ction f000(){return \"Sv\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Tn\";})(),(function f000(){return" ascii
    $s18 = ";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"ZFe\";})(),(function f" ascii
    $s19 = "000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg" ascii
    $s20 = "\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Wb\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}