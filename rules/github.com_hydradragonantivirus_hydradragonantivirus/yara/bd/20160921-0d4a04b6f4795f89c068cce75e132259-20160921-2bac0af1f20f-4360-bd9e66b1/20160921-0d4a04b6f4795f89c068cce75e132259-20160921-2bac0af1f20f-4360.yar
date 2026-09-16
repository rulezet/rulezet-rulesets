rule _20160921_0d4a04b6f4795f89c068cce75e132259_20160921_2bac0af1f20f_4360 {
  meta:
    description = "datamaliciousorder - from files 20160921_0d4a04b6f4795f89c068cce75e132259.js, 20160921_2bac0af1f20f4cf23b85236dea7e2f73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e80f63f8ef5a9b52f119cc58d120fd7d74784d15d23ddc339948cb92383c800c"
    hash2       = "ac846ac68af7b06cbf71b32cbfb1cee6c1f6cd131d52124bb877e0b27979fd81"

  strings:
    $s1 = "(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Zy\";})(),(function fuck(" ascii
    $s2 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"O" ascii
    $s3 = ";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"ADy\";})(),(function fu" ascii
    $s4 = "(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Nm\";}" ascii
    $s5 = ")(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}