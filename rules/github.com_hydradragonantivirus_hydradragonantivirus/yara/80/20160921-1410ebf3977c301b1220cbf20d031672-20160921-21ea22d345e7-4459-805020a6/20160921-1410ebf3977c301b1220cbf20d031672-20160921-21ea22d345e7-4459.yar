rule _20160921_1410ebf3977c301b1220cbf20d031672_20160921_21ea22d345e7_4459 {
  meta:
    description = "datamaliciousorder - from files 20160921_1410ebf3977c301b1220cbf20d031672.js, 20160921_21ea22d345e757ea2f8e6336a9555502.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bba6a8e474a809cf21b57641f08c798b1175b5bb510dcebc8d2284017c4579ab"
    hash2       = "e8743d09e1e870afab5e1ecd8d21f82873a9da6a025b74f14bc65477cea8f023"

  strings:
    $s1 = "(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck(" ascii
    $s2 = "n \"IPu\";})(),(function fuck(){return \"Ff\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s3 = "turn \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(" ascii
    $s4 = "function fuck(){return \"Mw\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){ret" ascii
    $s5 = "Go\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"OPz\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}