rule _20160831_db70e810d4c3d3674647678d28336634_20160831_ee454f06cb3f_129 {
  meta:
    description = "datamaliciousorder - from files 20160831_db70e810d4c3d3674647678d28336634.js, 20160831_ee454f06cb3f3dd2ae74c15ed14451c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5847d9d343a11480f1cc67feb27c84344631c19d3ec15fa35d1d5396075fec5d"
    hash2       = "83d2f448bbb32921b13a5d214c9d77a6893011f127835f1a9c60c64a4e361907"

  strings:
    $s1 = "aver!!!!!!Ug6shut-the-fuck-up-motherfucking-aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfuck" ascii
    $s2 = "aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfuck" ascii
    $s3 = "aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!KVj7shut-the-fuck-up-motherfuc" ascii
    $s4 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Apshut-the-fuck-up-motherfucking" ascii
    $s5 = "aver!!!!!!So2shut-the-fuck-up-motherfucking-aver!!!!!!UXg3shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuc" ascii
    $s6 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucki" ascii
    $s7 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!SJjshut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfuckin" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}