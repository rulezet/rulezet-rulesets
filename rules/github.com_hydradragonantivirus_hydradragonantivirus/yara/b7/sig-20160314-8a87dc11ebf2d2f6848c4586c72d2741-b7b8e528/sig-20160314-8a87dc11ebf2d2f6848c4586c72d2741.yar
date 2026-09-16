rule sig_20160314_8a87dc11ebf2d2f6848c4586c72d2741 {
  meta:
    description = "datamaliciousorder - file 20160314_8a87dc11ebf2d2f6848c4586c72d2741.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56b819e9f444b975e6e6f8f7bbd959b0e56e126d9e8823b438840f2dacf6b8db"

  strings:
    $s1  = "var oZ = true  , cVKX = XoP[7] + XoP[9] + XoP[11];" fullword ascii
    $s2  = "return Azepeyw[0] + Azepeyw[2] + Azepeyw[4] + \".F\" + Azepeyw[7] + Azepeyw[9] + Azepeyw[12] + Azepeyw[14];" fullword ascii
    $s3  = "var Azepeyw = \"Sc jbSFezh r ltHGEDWIx ipting xOaAwGT uKK ile RPTVaAfdVylrRr System Iu Pewhi Obj SdzcHn ect ScclloJ ZdAyq\".spli" ascii
    $s4  = "var Azepeyw = \"Sc jbSFezh r ltHGEDWIx ipting xOaAwGT uKK ile RPTVaAfdVylrRr System Iu Pewhi Obj SdzcHn ect ScclloJ ZdAyq\".spli" ascii
    $s5  = "var XoP = (\"2.XMLHTTP NZaGLjw pStQd XML ream St wdhYOAuv AD tEAfRTY O Iymv D\").split(\" \");" fullword ascii
    $s6  = "WnStv.open(vAdTU,vbKzh,false);" fullword ascii
    $s7  = "function mxtx(XeAgr) {" fullword ascii
    $s8  = "if (E >= Sntsd.length) {break;}" fullword ascii
    $s9  = "return XeAgr.status;" fullword ascii
    $s10 = "function OuPj(zPKFw) {" fullword ascii
    $s11 = "function OyboFpOx(mER) {" fullword ascii
    $s12 = "if(j>=O.length) {break;}" fullword ascii
    $s13 = "function UmokmBt(DIvD,OOAeq) {" fullword ascii
    $s14 = "function rbCH(uFtkC) {" fullword ascii
    $s15 = "return XzDi.responseBody;" fullword ascii
    $s16 = "if (OROLM > 168375-602){return true;} else {return false;}" fullword ascii
    $s17 = "function SgOguNDyf() {" fullword ascii
    $s18 = "function vsqb(xINyg,Xxpsk) {" fullword ascii
    $s19 = "return EZkSlfO" fullword ascii
    $s20 = "if (AquVO == 333-133){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}