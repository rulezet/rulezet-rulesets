rule _20160921_47da6150745eccf8bd846591c67ec5e7_20160921_527d7c375697_1115 {
  meta:
    description = "datamaliciousorder - from files 20160921_47da6150745eccf8bd846591c67ec5e7.js, 20160921_527d7c3756974f804734da343b6b6f0e.js, 20160921_6a2eea5014c6e10514154c4a8ee7c1be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a6547815adb02f36991578330e4cb005f8225b3a8e4c85d5e2c5907a22e325c"
    hash2       = "7d2dd725d314277b3b7cf1c94ae8894dce1d36430ff22819c2fecb47f14c3f43"
    hash3       = "b1fa490690ec2cf24ba4236d1fa675827bce812ac4cd92a59a9b5261b979f8a3"

  strings:
    $s1  = "urn \"QDg\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"XTn\";})(),(" ascii
    $s2  = "),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){" ascii
    $s3  = "function f000(){return \"Lp\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"RPt\";})(),(function f000(){re" ascii
    $s4  = ",(function f000(){return \"DAp\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nx\";})(),(function f000(){r" ascii
    $s5  = ";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vj\";})(),(function f00" ascii
    $s6  = "0(){return \"RLk\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\"" ascii
    $s7  = "ction f000(){return \"Vu\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii
    $s8  = "ZGq\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"TRc\";})(),(funct" ascii
    $s9  = "nction f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(),(function f000(){retur" ascii
    $s10 = "ction f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){retu" ascii
    $s11 = "00(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Kw\"" ascii
    $s12 = "eturn \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})()," ascii
    $s13 = "\"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"KDh\";})(),(func" ascii
    $s14 = "000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"HJ" ascii
    $s15 = "0(){return \"Iq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Mc\";}" ascii
    $s16 = "),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000()" ascii
    $s17 = "n\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"DIa\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}