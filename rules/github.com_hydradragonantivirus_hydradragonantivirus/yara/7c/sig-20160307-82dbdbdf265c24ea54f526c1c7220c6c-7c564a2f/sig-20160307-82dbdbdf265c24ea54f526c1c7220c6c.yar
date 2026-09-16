rule sig_20160307_82dbdbdf265c24ea54f526c1c7220c6c {
  meta:
    description = "datamaliciousorder - file 20160307_82dbdbdf265c24ea54f526c1c7220c6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17593d59829c57b79d49bee38f78ccf13299f3364e9afcc55f89b9755d9c167d"

  strings:
    $s1  = "var RxWyDAI = \"Sc CoTmHFL r lftqNqMOw ipting qRiQQcL KYA ile HnQafMIhwrYCdi System ti pAnyq Obj CxCyIK ect ULAjUBg\".split(\" " ascii
    $s2  = "function cltAMOvIy(TtVlQfFtprX) {" fullword ascii
    $s3  = "return RxWyDAI[0] + RxWyDAI[2] + RxWyDAI[4] + \".F\" + RxWyDAI[7] + RxWyDAI[9] + RxWyDAI[12] + RxWyDAI[14];" fullword ascii
    $s4  = "var TF = true  , wWZX = bkY[7] + bkY[9] + bkY[11];" fullword ascii
    $s5  = "var bkY = (\"2.XMLHTTP fOmymsT AnXTZ XML ream St beWDQSlO AD vbPMYoH O vCXG D\").split(\" \");" fullword ascii
    $s6  = "SsYkJ.open(llEpI,heJMc,false);" fullword ascii
    $s7  = "if (m >= MYCsK.length) {break;}" fullword ascii
    $s8  = "return new ActiveXObject(pAqkxr);" fullword ascii
    $s9  = "return ayzOO.status;" fullword ascii
    $s10 = "function PGHS(wmsLS) {" fullword ascii
    $s11 = "function yCdNWtTlY(fWZgu,dzVZN,SODCo,mNdF) {" fullword ascii
    $s12 = "function PwYdejPD(gov) {" fullword ascii
    $s13 = "if(J>=r.length) {break;}" fullword ascii
    $s14 = "function IunKjcF(Qtsc) {" fullword ascii
    $s15 = "return CmuAe.replace(new RegExp('!','g'), 'e');" fullword ascii
    $s16 = "function DXyS(wJgct,nZorE) {" fullword ascii
    $s17 = "function qSQE(UkQYc) {" fullword ascii
    $s18 = "function ZEGO(SsYkJ,heJMc,llEpI) {" fullword ascii
    $s19 = "return mSpgOjV" fullword ascii
    $s20 = "function qmgjyWQ(mIUq) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}