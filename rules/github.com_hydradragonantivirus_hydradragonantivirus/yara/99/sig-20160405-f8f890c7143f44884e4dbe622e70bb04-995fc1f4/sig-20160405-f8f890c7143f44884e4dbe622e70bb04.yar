rule sig_20160405_f8f890c7143f44884e4dbe622e70bb04 {
  meta:
    description = "datamaliciousorder - file 20160405_f8f890c7143f44884e4dbe622e70bb04.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1174f33b9e7555368ff2e851d879f8e4ef3600fffc02ec9d9f363ff1ba21bbb2"

  strings:
    $s1  = "var eX = true  , ZQId = SpY[7] + SpY[9] + SpY[11];" fullword ascii
    $s2  = "var SpY = (\"2.XMLHTTP UKksmwA nDNYV XML ream St fGYuzaZv AD VfVkSSf O XVSd D\").split(\" \");" fullword ascii
    $s3  = "if (gGloG == 829-629){return true;} else {return false;}" fullword ascii
    $s4  = "function ajZk(gGloG) {" fullword ascii
    $s5  = "bGyE.open(YqYkx,Mlwir,false);" fullword ascii
    $s6  = "function EMVO(ydfpX,nAIyS) {" fullword ascii
    $s7  = "function KJLHf(rCFsSr) {" fullword ascii
    $s8  = "return DGztM.status;" fullword ascii
    $s9  = "function myaK(ckdeh,AxXMo) {" fullword ascii
    $s10 = "function KjGjE(qhNQQXGu,lrTN) {" fullword ascii
    $s11 = "if (v >= hrntE.length) {break;}" fullword ascii
    $s12 = "if(o>=q.length) {break;}" fullword ascii
    $s13 = "if (XdnDa > 162237-501){return true;} else {return false;}" fullword ascii
    $s14 = "function YUrG(DGztM) {" fullword ascii
    $s15 = "function xRIdg(jHDKYE) {" fullword ascii
    $s16 = "return vxQO;" fullword ascii
    $s17 = "function DoYUmYF(wTZb,WhzKZ) {" fullword ascii
    $s18 = "function pHmSEceaJ(gsRdbBuBSoD) {" fullword ascii
    $s19 = "function bVuH(XdnDa) {" fullword ascii
    $s20 = "return new ActiveXObject(OMzB);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}