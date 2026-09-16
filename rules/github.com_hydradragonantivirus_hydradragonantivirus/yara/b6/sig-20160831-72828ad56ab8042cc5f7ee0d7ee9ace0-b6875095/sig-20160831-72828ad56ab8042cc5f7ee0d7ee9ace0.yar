rule sig_20160831_72828ad56ab8042cc5f7ee0d7ee9ace0 {
  meta:
    description = "datamaliciousorder - file 20160831_72828ad56ab8042cc5f7ee0d7ee9ace0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1c873b59f7fad7e2f5418c8150c786766e36a94467865bf74f31cffe85fd5fe"

  strings:
    $s1  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Fkshut-the-fuck-up-motherfucking" ascii
    $s2  = "aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking" ascii
    $s3  = "aver!!!!!!Vdshut-the-fuck-up-motherfucking-aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!So2shut-the-fuck-up-motherfucki" ascii
    $s4  = "aver!!!!!!PYcshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!XDqshut-the-fuck-up-motherfuck" ascii
    $s5  = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Cxshut-the-fuck-up-motherfucking-aver!!!!!!TOyshut-the-fuck-up-motherfuckin" ascii
    $s6  = "aver!!!!!!Qd0shut-the-fuck-up-motherfucking-aver!!!!!!Rfshut-the-fuck-up-motherfucking-aver!!!!!!Qf2shut-the-fuck-up-motherfucki" ascii
    $s7  = "aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!QIbshut-the-fuck-up-motherfucking-aver!!!!!!Tx7shut-the-fuck-up-motherfucki" ascii
    $s8  = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Ja2shut-the-fuck-up-motherfucking-aver!!!!!!Rushut-the-fuck-up-motherfucki" ascii
    $s9  = "aver!!!!!!XDqshut-the-fuck-up-motherfucking-aver!!!!!!OEqshut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfuck" ascii
    $s10 = "aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!XBhshut-the-fuck-up-motherfuc" ascii
    $s11 = "aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Ztshut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherfucki" ascii
    $s12 = "aver!!!!!!Eeshut-the-fuck-up-motherfucking-aver!!!!!!Leshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking" ascii
    $s13 = "aver!!!!!!GXo7shut-the-fuck-up-motherfucking-aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!MHz2shut-the-fuck-up-motherfuc" ascii
    $s14 = "aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!NVmshut-the-fuck-up-motherfucki" ascii
    $s15 = "aver!!!!!!Ib3shut-the-fuck-up-motherfucking-aver!!!!!!Kjshut-the-fuck-up-motherfucking-aver!!!!!!Fv3shut-the-fuck-up-motherfucki" ascii
    $s16 = "aver!!!!!!GRc7shut-the-fuck-up-motherfucking-aver!!!!!!GNp9shut-the-fuck-up-motherfucking-aver!!!!!!GXo7shut-the-fuck-up-motherf" ascii
    $s17 = "aver!!!!!!YZcshut-the-fuck-up-motherfucking-aver!!!!!!Gu3shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucki" ascii
    $s18 = "aver!!!!!!LYk5shut-the-fuck-up-motherfucking-aver!!!!!!Lyshut-the-fuck-up-motherfucking-aver!!!!!!Lyshut-the-fuck-up-motherfucki" ascii
    $s19 = "aver!!!!!!Rnshut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfucking-aver!!!!!!Bishut-the-fuck-up-motherfucking" ascii
    $s20 = "aver!!!!!!NEbshut-the-fuck-up-motherfucking-aver!!!!!!DBa4shut-the-fuck-up-motherfucking-aver!!!!!!Xlshut-the-fuck-up-motherfuck" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}