rule _20160921_5f7be0b4d162caa40e1fc5a06f9f867a_20160921_ce9aea7615ba_3838 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f7be0b4d162caa40e1fc5a06f9f867a.js, 20160921_ce9aea7615ba4a71719a9c0d7f838fc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a6e02fec1a6c5d0a6813da97edfb28eb017c5563b8e8c2205eb08ae1c6ec4e3"
    hash2       = "1dfc225800b3b802cbdd9312a3198f5eb4bbcdb06d5f9ffd026bb3fb4f5cf4e6"

  strings:
    $s1 = "nction fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retu" ascii
    $s2 = "fuck(){return \"FJs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"G" ascii
    $s3 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Za\";})(),(function fuc" ascii
    $s4 = "rn \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s5 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){ret" ascii
    $s6 = "b\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}