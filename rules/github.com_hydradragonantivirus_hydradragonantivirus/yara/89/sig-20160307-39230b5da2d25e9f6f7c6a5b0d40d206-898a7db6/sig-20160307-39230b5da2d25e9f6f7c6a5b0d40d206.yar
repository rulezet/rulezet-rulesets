rule sig_20160307_39230b5da2d25e9f6f7c6a5b0d40d206 {
  meta:
    description = "datamaliciousorder - file 20160307_39230b5da2d25e9f6f7c6a5b0d40d206.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86ea95b78d677b1248e6f909486d267422765357956677a8dae3616c640b276b"

  strings:
    $s1  = "var Qu = true  , lHoo = jYt[7] + jYt[9] + jYt[11];" fullword ascii
    $s2  = "return VyrIVgd[0] + VyrIVgd[2] + VyrIVgd[4] + \".F\" + VyrIVgd[7] + VyrIVgd[9] + VyrIVgd[12] + VyrIVgd[14];" fullword ascii
    $s3  = "var jYt = (\"2.XMLHTTP YqXWVYa sofKM XML ream St IYHFHwLC AD RKYMPVf O AbNw D\").split(\" \");" fullword ascii
    $s4  = "FlVuq.open(EXJQo,lRgau,false);" fullword ascii
    $s5  = "var VyrIVgd = \"Sc qonQABk r oBMGAqaLe ipting fgkfKlH GZT ile ZSHGFGSsQygGjk System PK NeALp Obj FltHRU ect nKCLmEX\".split(\" " ascii
    $s6  = "function JjxJI(IiOoyp) {" fullword ascii
    $s7  = "function ZaPE(gxiUS) {" fullword ascii
    $s8  = "return new ActiveXObject(IiOoyp);" fullword ascii
    $s9  = "function AiULrcgqU(QSNwh,tIoeV,PpQTu,OsDv) {" fullword ascii
    $s10 = "if(m>=c.length) {break;}" fullword ascii
    $s11 = "if (Q >= GBKaF.length) {break;}" fullword ascii
    $s12 = "return LVMEZ;" fullword ascii
    $s13 = "function lwcCnmZiK(suvjganYKUM) {" fullword ascii
    $s14 = "return uuT.size;" fullword ascii
    $s15 = "if (((new Date())>0,7677761888)) {" fullword ascii
    $s16 = "function zRpeBCJn(uuT) {" fullword ascii
    $s17 = "function PjNQ(HYZhC) {" fullword ascii
    $s18 = "function ethB(aPUfc,crDhA) {" fullword ascii
    $s19 = "rqw = m; break; " fullword ascii
    $s20 = "return Gtauf.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}