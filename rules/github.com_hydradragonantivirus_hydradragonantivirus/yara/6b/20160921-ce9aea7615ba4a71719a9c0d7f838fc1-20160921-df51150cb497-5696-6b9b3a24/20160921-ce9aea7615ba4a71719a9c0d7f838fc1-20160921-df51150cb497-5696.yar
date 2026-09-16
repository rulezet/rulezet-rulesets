rule _20160921_ce9aea7615ba4a71719a9c0d7f838fc1_20160921_df51150cb497_5696 {
  meta:
    description = "datamaliciousorder - from files 20160921_ce9aea7615ba4a71719a9c0d7f838fc1.js, 20160921_df51150cb4977f20502f85bfda11d939.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dfc225800b3b802cbdd9312a3198f5eb4bbcdb06d5f9ffd026bb3fb4f5cf4e6"
    hash2       = "81cf54f681cedb1b59ee2e355f226c046ac83c55ad32ce5241949279bb194bf1"

  strings:
    $s1 = "turn \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GWo\";})()," ascii
    $s2 = "})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"DAa\";})(),(function fu" ascii
    $s3 = "return \"Wo0\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Ar\";})()" ascii
    $s4 = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return " ascii
    $s5 = "a\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ve\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}