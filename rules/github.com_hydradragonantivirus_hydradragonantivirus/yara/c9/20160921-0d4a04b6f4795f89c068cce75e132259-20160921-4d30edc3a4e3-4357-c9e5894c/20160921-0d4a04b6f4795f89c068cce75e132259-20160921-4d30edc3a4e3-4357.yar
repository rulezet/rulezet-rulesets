rule _20160921_0d4a04b6f4795f89c068cce75e132259_20160921_4d30edc3a4e3_4357 {
  meta:
    description = "datamaliciousorder - from files 20160921_0d4a04b6f4795f89c068cce75e132259.js, 20160921_4d30edc3a4e3226feee5b6289df9e399.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e80f63f8ef5a9b52f119cc58d120fd7d74784d15d23ddc339948cb92383c800c"
    hash2       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"

  strings:
    $s1 = "ck(){return \"AUx\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MOj" ascii
    $s2 = "),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck()" ascii
    $s3 = "{return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jh\";})" ascii
    $s4 = "fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"A" ascii
    $s5 = "{return \"Ot\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}