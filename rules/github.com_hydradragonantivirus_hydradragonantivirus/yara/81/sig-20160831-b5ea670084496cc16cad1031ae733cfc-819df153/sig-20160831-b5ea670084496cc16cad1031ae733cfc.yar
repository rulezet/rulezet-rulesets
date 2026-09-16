rule sig_20160831_b5ea670084496cc16cad1031ae733cfc {
  meta:
    description = "datamaliciousorder - file 20160831_b5ea670084496cc16cad1031ae733cfc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90668d02923157b4f506a6e15dfe3d4ea3de731a339973dfc316ecdb60d204c0"

  strings:
    $s1  = "aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfucki" ascii
    $s2  = "aver!!!!!!Ncshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking-aver!!!!!!UHoshut-the-fuck-up-motherfuckin" ascii
    $s3  = "aver!!!!!!ASy5shut-the-fuck-up-motherfucking-aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuck" ascii
    $s4  = "aver!!!!!!Pj2shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Dt1shut-the-fuck-up-motherfucki" ascii
    $s5  = "aver!!!!!!Ptshut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s6  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!Ptshut-the-fuck-up-motherfucki" ascii
    $s7  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfuckin" ascii
    $s8  = "t-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s9  = "aver!!!!!!TOyshut-the-fuck-up-motherfucking-aver!!!!!!APzshut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfuck" ascii
    $s10 = "the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Prshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s11 = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!Opshut-the-fuck-up-motherfucking-aver!!!!!!Jjshut-the-fuck-up-motherfuckin" ascii
    $s12 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s13 = "aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfuckin" ascii
    $s14 = "aver!!!!!!HOx7shut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuck" ascii
    $s15 = "aver!!!!!!NVmshut-the-fuck-up-motherfucking-aver!!!!!!XEpshut-the-fuck-up-motherfucking-aver!!!!!!Ptshut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!Nl2shut-the-fuck-up-motherfucking-aver!!!!!!TOyshut-the-fuck-up-motherfuck" ascii
    $s17 = "aver!!!!!!Dt1shut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfucking-aver!!!!!!Jg9shut-the-fuck-up-motherfuck" ascii
    $s18 = "t-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ogshut-the-fuck-up-motherfucking-aver!!!!!!Rush" ascii
    $s19 = "aver!!!!!!Lbshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s20 = "aver!!!!!!DLr7shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Zh4shut-the-fuck-up-motherfuck" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}