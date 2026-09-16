rule _20160831_0af40ab6ce2198b95ff522d2d198d0f7_20160831_fbba7bc82776_316 {
  meta:
    description = "datamaliciousorder - from files 20160831_0af40ab6ce2198b95ff522d2d198d0f7.js, 20160831_fbba7bc827762215c832c68852a051a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05e83d961389942738433438cffc07cce8ea0d22aa0e94f6f6285740d8a203af"
    hash2       = "711b84d59101c108fcd2e91808c167041b0f1cfb91cccaa1478741f497e227e5"

  strings:
    $s1 = "aver!!!!!!TOyshut-the-fuck-up-motherfucking-aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfuck" ascii
    $s2 = "aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Iishut-the-fuck-up-motherfucking-aver!!!!!!Ib3shut-the-fuck-up-motherfuckin" ascii
    $s3 = "aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!GNp9shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuck" ascii
    $s4 = "aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!LYk5shut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfuck" ascii
    $s5 = "aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!Ck3shut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfuck" ascii
    $s6 = "aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!Qf2shut-the-fuck-up-motherfucki" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}