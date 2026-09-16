rule sig_20160308_48bcb21a8a7654940e0a2ee9f96e430e {
  meta:
    description = "datamaliciousorder - file 20160308_48bcb21a8a7654940e0a2ee9f96e430e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a907039a9228f5ddf2a7bf41c7e4f680897d13344dad88afefbd2f9b8a216ccf"

  strings:
    $s1  = "var Wo = true  , vGax = jYx[7] + jYx[9] + jYx[11];" fullword ascii
    $s2  = "return yKUbiAy[0] + yKUbiAy[2] + yKUbiAy[4] + \".F\" + yKUbiAy[7] + yKUbiAy[9] + yKUbiAy[12] + yKUbiAy[14];" fullword ascii
    $s3  = "var yKUbiAy = \"Sc yDsEYKb r ufCVWmCxs ipting qvEOlRC vwV ile TtRPuWITgbSTIh System Fw Xcnvo Obj fCtgKo ect INMpCqr\".split(\" " ascii
    $s4  = "var jYx = (\"2.XMLHTTP NxyGrYF ZKzqW XML ream St fOjwsSnJ AD ezVSuhT O jcMq D\").split(\" \");" fullword ascii
    $s5  = "EetnD.open(Zqnbx,wMYcq,false);" fullword ascii
    $s6  = "function CViU(moxef) {" fullword ascii
    $s7  = "function kNJe(RzGdm) {" fullword ascii
    $s8  = "return LnVoikO" fullword ascii
    $s9  = "function OlvNVhYT(RQd) {" fullword ascii
    $s10 = "if(b>=R.length) {break;}" fullword ascii
    $s11 = "return BgryN;" fullword ascii
    $s12 = "function GUTotVqeb(gweeP,mBmJb,qZrHL,xXlZ) {" fullword ascii
    $s13 = "function hSHx(Ahmdz) {" fullword ascii
    $s14 = "function ZXDF(cZgih) {" fullword ascii
    $s15 = "function pqKi(XMdai,LEiZY) {" fullword ascii
    $s16 = "ney = b; break; " fullword ascii
    $s17 = "function RLWx(EetnD,wMYcq,Zqnbx) {" fullword ascii
    $s18 = "if (Ahmdz == 912-712){return true;} else {return false;}" fullword ascii
    $s19 = "return new ActiveXObject(nLhCml);" fullword ascii
    $s20 = "function XMBaJUEg() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}