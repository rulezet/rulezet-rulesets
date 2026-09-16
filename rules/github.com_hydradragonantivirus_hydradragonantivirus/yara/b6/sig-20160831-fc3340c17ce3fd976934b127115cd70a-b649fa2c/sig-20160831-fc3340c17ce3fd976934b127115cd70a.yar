rule sig_20160831_fc3340c17ce3fd976934b127115cd70a {
  meta:
    description = "datamaliciousorder - file 20160831_fc3340c17ce3fd976934b127115cd70a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a576f727222ef1057672e4050dc1594716a809a246042d47ebb6ebbdb7410fd9"

  strings:
    $s1  = "aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Bishut-the-fuck-up-motherfuckin" ascii
    $s2  = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!Qf2shut-the-fuck-up-motherfucking-aver!!!!!!Nsshut-the-fuck-up-motherfucking-aver!!!!!!Lyshut-the-fuck-up-motherfuckin" ascii
    $s4  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucking" ascii
    $s5  = "aver!!!!!!Tx7shut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!FCwshut-the-fuck-up-motherfucki" ascii
    $s6  = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfuckin" ascii
    $s7  = "aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!Ya2shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfuck" ascii
    $s8  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Gcshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking" ascii
    $s9  = "aver!!!!!!XGx6shut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!YZcshut-the-fuck-up-motherfuc" ascii
    $s10 = "aver!!!!!!Mu8shut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuckin" ascii
    $s11 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking" ascii
    $s12 = "aver!!!!!!XEpshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuck" ascii
    $s13 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Apshut-the-fuck-up-motherfucking-aver!!!!!!Mu8shut-the-fuck-up-motherfucki" ascii
    $s14 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Cxshut-the-fuck-up-motherfucking-aver!!!!!!Ug6shut-the-fuck-up-motherfuckin" ascii
    $s15 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Hv0shut-the-fuck-up-motherfucking-aver!!!!!!DRushut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Apshut-the-fuck-up-motherfucking-aver!!!!!!Cxshut-the-fuck-up-motherfucking" ascii
    $s17 = "the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s18 = "aver!!!!!!XEpshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfuc" ascii
    $s19 = "-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s20 = "aver!!!!!!UHoshut-the-fuck-up-motherfucking-aver!!!!!!Nsshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfucki" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}