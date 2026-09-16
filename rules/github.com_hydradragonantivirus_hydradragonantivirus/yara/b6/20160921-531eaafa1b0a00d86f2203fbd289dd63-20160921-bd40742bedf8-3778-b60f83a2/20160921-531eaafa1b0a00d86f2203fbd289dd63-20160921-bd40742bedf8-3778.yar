rule _20160921_531eaafa1b0a00d86f2203fbd289dd63_20160921_bd40742bedf8_3778 {
  meta:
    description = "datamaliciousorder - from files 20160921_531eaafa1b0a00d86f2203fbd289dd63.js, 20160921_bd40742bedf80aa0091b1fafd0a7ba4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28500022264ce61d9d988db6f8ddee46acc7dea6f898510f532ee48f87a0c93"
    hash2       = "85233a675e78f03dbcaaf2a32253b0d4a36e5c5e7008041477e560a514d38729"

  strings:
    $s1 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return" ascii
    $s2 = " fuck(){return \"Tv\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"IP" ascii
    $s3 = "k(){return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Tv\"" ascii
    $s4 = "ck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Cd" ascii
    $s5 = " fuck(){return \"Za\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"P" ascii
    $s6 = ")(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}