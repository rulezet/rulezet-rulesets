rule _20160921_47da6150745eccf8bd846591c67ec5e7_20160921_6a2eea5014c6_5078 {
  meta:
    description = "datamaliciousorder - from files 20160921_47da6150745eccf8bd846591c67ec5e7.js, 20160921_6a2eea5014c6e10514154c4a8ee7c1be.js, 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a6547815adb02f36991578330e4cb005f8225b3a8e4c85d5e2c5907a22e325c"
    hash2       = "b1fa490690ec2cf24ba4236d1fa675827bce812ac4cd92a59a9b5261b979f8a3"
    hash3       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"

  strings:
    $s1 = "0(){return \"Lp\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";" ascii
    $s2 = "\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s3 = "\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f" ascii
    $s4 = "\"Iq\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Nv\";})(),(functio" ascii
    $s5 = "00(){return \"KXg\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}