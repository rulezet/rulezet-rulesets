rule sig_20160321_fede240aadaec7eac33bc0d6190bd01c {
  meta:
    description = "datamaliciousorder - file 20160321_fede240aadaec7eac33bc0d6190bd01c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba75a65f62983cee1094cf56320ffea6fc596edd701ef1adc963507317330117"

  strings:
    $s1  = "return WScript.CreateObject(ugQKK);" fullword ascii
    $s2  = "var ad = true  , wAVa = Eqp[7] + Eqp[9] + Eqp[11];" fullword ascii
    $s3  = "return BhyrTzq[0] + BhyrTzq[2] + BhyrTzq[4] + \".F\" + BhyrTzq[7] + BhyrTzq[9] + BhyrTzq[12] + BhyrTzq[14];" fullword ascii
    $s4  = "var Eqp = (\"2.XMLHTTP TYaqjpW oGIaQ XML ream St OBJCGXUM AD zoJQgzC O hbNH D\").split(\" \");" fullword ascii
    $s5  = "var BhyrTzq = mGVgH(edLVlZrUwC+\" \"+\"System jW uTASj Obj AWRcMH ect KRScTby lWSRB\", \" \");" fullword ascii
    $s6  = "dHqEP.open(KoJXs,SWvSF,false);" fullword ascii
    $s7  = "aDE = y; break; " fullword ascii
    $s8  = "function KCzp(kuQXP) {" fullword ascii
    $s9  = "function sKUR(sWZfc) {" fullword ascii
    $s10 = "return djd.split(NjBDN);" fullword ascii
    $s11 = "if(y>=u.length) {break;}" fullword ascii
    $s12 = "function wXjx(kxgpt,uqYXR) {" fullword ascii
    $s13 = "return rErbqW.position=859-859;" fullword ascii
    $s14 = "function vZegg(lHOild) {" fullword ascii
    $s15 = "function ZXqP(oPGpx) {" fullword ascii
    $s16 = "function RtxZPDXx(nGL) {" fullword ascii
    $s17 = "function khoM(ugQKK) {" fullword ascii
    $s18 = "function trCy(VOJWI,tnMHW) {" fullword ascii
    $s19 = "function KbIUiDa(ETiU) {" fullword ascii
    $s20 = "return rqtt.ExpandEnvironmentStrings(OvznU);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}