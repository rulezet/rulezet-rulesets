rule _20160831_1042a63b00edd7d7c85cf4d5ed7ccf8e_20160831_afb9a753646e_86 {
  meta:
    description = "datamaliciousorder - from files 20160831_1042a63b00edd7d7c85cf4d5ed7ccf8e.js, 20160831_afb9a753646e5a9c8795c272fa4ca76b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "422f47949d0a388caebd3fc2e6f82ae01eb55e8eaacf33065c43197924595c38"
    hash2       = "574ab3769c7b1e69172ddcd71da8cbf656fb86289f86920ce5642ce90bf44af3"

  strings:
    $s1 = "aver!!!!!!OEishut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Cxshut-the-fuck-up-motherfuckin" ascii
    $s2 = "the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s3 = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking" ascii
    $s4 = "aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucking" ascii
    $s5 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!Dy2shut-the-fuck-up-motherfucki" ascii
    $s6 = "aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfuck" ascii
    $s7 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfuckin" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}