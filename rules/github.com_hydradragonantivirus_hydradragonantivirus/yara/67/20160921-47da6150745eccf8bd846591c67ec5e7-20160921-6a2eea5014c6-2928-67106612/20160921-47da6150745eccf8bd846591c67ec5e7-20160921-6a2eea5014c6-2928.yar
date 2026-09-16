rule _20160921_47da6150745eccf8bd846591c67ec5e7_20160921_6a2eea5014c6_2928 {
  meta:
    description = "datamaliciousorder - from files 20160921_47da6150745eccf8bd846591c67ec5e7.js, 20160921_6a2eea5014c6e10514154c4a8ee7c1be.js, 20160921_7cd473b59463126782b9a6cfaae72835.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a6547815adb02f36991578330e4cb005f8225b3a8e4c85d5e2c5907a22e325c"
    hash2       = "b1fa490690ec2cf24ba4236d1fa675827bce812ac4cd92a59a9b5261b979f8a3"
    hash3       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"

  strings:
    $s1 = "),(function f000(){return \"Kw\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){" ascii
    $s2 = "(function f000(){return \"MMz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"KXg\";})(),(function f000(){r" ascii
    $s3 = "})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"KXg\";})(),(function f000" ascii
    $s4 = " \"Wb\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(funct" ascii
    $s5 = "00(){return \"PTi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj" ascii
    $s6 = "n \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"KDh\";})(),(fun" ascii
    $s7 = "unction f000(){return \"KDh\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}