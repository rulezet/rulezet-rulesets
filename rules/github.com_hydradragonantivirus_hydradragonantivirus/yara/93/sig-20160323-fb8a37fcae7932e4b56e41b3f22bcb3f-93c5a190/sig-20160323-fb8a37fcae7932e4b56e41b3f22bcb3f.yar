rule sig_20160323_fb8a37fcae7932e4b56e41b3f22bcb3f {
  meta:
    description = "datamaliciousorder - file 20160323_fb8a37fcae7932e4b56e41b3f22bcb3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ce25e26b360c08d6f125d25dbd19ab41d49811f8edd6fec73eaa3cf47607760"

  strings:
    $s1  = "return WScript.CreateObject(QUzem);" fullword ascii
    $s2  = "var gM = true  , JHrl = HbT[7] + HbT[9] + HbT[11];" fullword ascii
    $s3  = "return ZMgnOsd[0] + ZMgnOsd[2] + ZMgnOsd[4] + \".F\" + ZMgnOsd[7] + ZMgnOsd[9] + ZMgnOsd[12] + ZMgnOsd[14];" fullword ascii
    $s4  = "var ZMgnOsd = AVVIl(zrtdDanTvd+\" \"+\"System wE krDVF Obj uIEuxM ect iEZnZzx hmqMI\", \" \");" fullword ascii
    $s5  = "var HbT = (\"2.XMLHTTP ztJfKpa zgSNs XML ream St zxCDguQt AD wWjgVZc O TyDN D\").split(\" \");" fullword ascii
    $s6  = "ffVx.open(KbcvE,poTNK,false);" fullword ascii
    $s7  = "function cZZb(AOdVG) {" fullword ascii
    $s8  = "return MFk.split(UyZXb);" fullword ascii
    $s9  = "function HDNM(jSLol,BTCBF) {" fullword ascii
    $s10 = "function smUL(EfcKU) {" fullword ascii
    $s11 = "return dlufuso(pn,UGXZK[897-891]+UGXZK[951-944]+UGXZK[267-259]);" fullword ascii
    $s12 = "return AOdVG.status;" fullword ascii
    $s13 = "return new ActiveXObject(GDju);" fullword ascii
    $s14 = "function KIIeLkLuw(ssRrI) {" fullword ascii
    $s15 = "function QMIAM(Lgiged) {" fullword ascii
    $s16 = "VBw = p; break; " fullword ascii
    $s17 = "function eQoA(VfBYU,BJHXM) {" fullword ascii
    $s18 = "if(p>=U.length) {break;}" fullword ascii
    $s19 = "if (MutkY == 755-555){return true;} else {return false;}" fullword ascii
    $s20 = "return pCzwnj/*XUfspJ2KRVKyu9ltGZdFFScCZ*/.position=385-385;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}