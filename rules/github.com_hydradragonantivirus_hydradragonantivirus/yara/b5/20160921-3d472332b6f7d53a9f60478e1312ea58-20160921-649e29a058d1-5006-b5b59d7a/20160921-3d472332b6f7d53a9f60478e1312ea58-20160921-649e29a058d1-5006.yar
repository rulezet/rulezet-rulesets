rule _20160921_3d472332b6f7d53a9f60478e1312ea58_20160921_649e29a058d1_5006 {
  meta:
    description = "datamaliciousorder - from files 20160921_3d472332b6f7d53a9f60478e1312ea58.js, 20160921_649e29a058d10c3bf9a5a5a06eb3b603.js, 20160921_9aa040f4b657816cc001fcf9a33be586.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afa09723c03c97cb533583268f8fb586a7ccfc3438d793acc59eedb90be55b5b"
    hash2       = "6565dca0eb9e0e467a96242f29a80c650cc40a8892572ce8c28bfd197ace7fd0"
    hash3       = "06edaae6cd03c231dca115449fcaf6955b5f70df34983f02383296a412f73538"

  strings:
    $s1 = "unction f000(){return \"Ot\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){ret" ascii
    $s2 = "000(){return \"GGn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KX" ascii
    $s3 = "i\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Kw\";})(),(function " ascii
    $s4 = "})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000" ascii
    $s5 = "n \"XTn\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}