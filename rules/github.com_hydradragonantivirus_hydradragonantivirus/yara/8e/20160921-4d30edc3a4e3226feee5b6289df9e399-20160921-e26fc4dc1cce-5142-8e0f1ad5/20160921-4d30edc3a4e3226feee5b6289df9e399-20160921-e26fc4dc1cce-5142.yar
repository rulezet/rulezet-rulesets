rule _20160921_4d30edc3a4e3226feee5b6289df9e399_20160921_e26fc4dc1cce_5142 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d30edc3a4e3226feee5b6289df9e399.js, 20160921_e26fc4dc1ccef911251bba0675c76ce0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"
    hash2       = "f1074dcd9f3ae62af13634c9f88af0a235b2e315a2697fc222ce96bad51ca1a1"

  strings:
    $s1 = "n \"GWo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s2 = "\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"NKq\";})(),(function " ascii
    $s3 = "nction fuck(){return \"Vf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return" ascii
    $s4 = ")(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck" ascii
    $s5 = "turn \"Tv\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}