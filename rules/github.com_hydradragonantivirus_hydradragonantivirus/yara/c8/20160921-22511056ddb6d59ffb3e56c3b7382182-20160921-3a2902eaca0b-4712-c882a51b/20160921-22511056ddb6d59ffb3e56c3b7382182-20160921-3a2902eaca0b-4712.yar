rule _20160921_22511056ddb6d59ffb3e56c3b7382182_20160921_3a2902eaca0b_4712 {
  meta:
    description = "datamaliciousorder - from files 20160921_22511056ddb6d59ffb3e56c3b7382182.js, 20160921_3a2902eaca0b2b91120958418b46c844.js, 20160921_56560f8d7ec61c150afb741a4a7975e2.js, 20160921_ef83849d63779003debb3d7ec32b193e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a5f7b2bfdf24defc0d363114441d0c0a0452fd599bf21d359b1b5f068dfc567"
    hash2       = "063bab1922376d926db97bdcd4342c2e9b0f2ec98d9fad81c2a3f86537c82b07"
    hash3       = "ba922e4e746eb45b8e98a88ec3071072c0850dbd5e2a359302331e1ae65210fb"
    hash4       = "8c488afd3d971ee89eb15305d884bacb01b91fa70760bea0aaf808120622dfa3"

  strings:
    $s1 = "){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";" ascii
    $s2 = "Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(functio" ascii
    $s3 = "u\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(functio" ascii
    $s4 = "uck(){return \"Tv\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";" ascii
    $s5 = "n \"MIl\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}