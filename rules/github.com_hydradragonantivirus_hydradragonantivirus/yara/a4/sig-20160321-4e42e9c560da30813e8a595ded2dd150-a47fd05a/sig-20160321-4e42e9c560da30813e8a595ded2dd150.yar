rule sig_20160321_4e42e9c560da30813e8a595ded2dd150 {
  meta:
    description = "datamaliciousorder - file 20160321_4e42e9c560da30813e8a595ded2dd150.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "baec2fdb4bf38513016bece99cf63afe0d90b403246c4a32e1130013d040e5a9"

  strings:
    $s1  = "return WScript.CreateObject(jtkUp);" fullword ascii
    $s2  = "function EcUVYFubQ(OPDKQicgETk) {" fullword ascii
    $s3  = "var dt = true  , sCyt = GXQ[7] + GXQ[9] + GXQ[11];" fullword ascii
    $s4  = "return JSgqYbw[0] + JSgqYbw[2] + JSgqYbw[4] + \".F\" + JSgqYbw[7] + JSgqYbw[9] + JSgqYbw[12] + JSgqYbw[14];" fullword ascii
    $s5  = "var IMF = CFXr(sCyt + \"B.\" + GXQ[5]+(140599, GXQ[4]));" fullword ascii
    $s6  = "mjela.open(RMnEK,wRWjo,false);" fullword ascii
    $s7  = "var GXQ = (\"2.XMLHTTP osuErYt bSvTL XML ream St RWOVNlvV AD ksqdGQb O AWXd D\").split(\" \");" fullword ascii
    $s8  = "var JSgqYbw = xjBdU(ePcEBnUFhI+\" \"+\"System Mm vtkIJ Obj mMhAqV ect lqECvOb mneXF\", \" \");" fullword ascii
    $s9  = "uRA = h; break; " fullword ascii
    $s10 = "function uOwvK(sMISqV) {" fullword ascii
    $s11 = "return typzp;" fullword ascii
    $s12 = "function xjBdU(YJw,ZSoBU) {" fullword ascii
    $s13 = "return YJw.split(ZSoBU);" fullword ascii
    $s14 = "if(h>=B.length) {break;}" fullword ascii
    $s15 = "if (SHQAK == 454-254){return true;} else {return false;}" fullword ascii
    $s16 = "function ykWM(BqChW,bjFIj) {" fullword ascii
    $s17 = "if (fhIdU > 181714-116){return true;} else {return false;}" fullword ascii
    $s18 = "function Pltx(FFzQM) {" fullword ascii
    $s19 = "function ktwUbhn(aMEF,qgtpR) {" fullword ascii
    $s20 = "function zrLK(mjela,wRWjo,RMnEK) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}