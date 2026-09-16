rule sig_20160315_cfa81c05e20eb77e6a8622aa5cea88ed {
  meta:
    description = "datamaliciousorder - file 20160315_cfa81c05e20eb77e6a8622aa5cea88ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd055feeca58a72f3804a3eda208f05e24e5f9a6f8be50e1f4b284446d6589ee"

  strings:
    $s1  = "return NmLygrh[0] + NmLygrh[2] + NmLygrh[4] + \".F\" + NmLygrh[7] + NmLygrh[9] + NmLygrh[12] + NmLygrh[14];" fullword ascii
    $s2  = "var kA = true  , zyDE = pgJ[7] + pgJ[9] + pgJ[11];" fullword ascii
    $s3  = "var NmLygrh = DlepR(\"Sc qIOmVgq r bXUhSLEvJ ipting oZLyfQs tme ile cDyWTQhWcbiQxb System zp Jpgjp Obj BxBlxl ect JTFXqcP ejfPx" ascii
    $s4  = "HCxZY.open(kEJYI,MnEui,false);" fullword ascii
    $s5  = "var pgJ = (\"2.XMLHTTP VeIiTat rCvHg XML ream St IXiGHRHl AD egudkdd O IwRS D\").split(\" \");" fullword ascii
    $s6  = "var NmLygrh = DlepR(\"Sc qIOmVgq r bXUhSLEvJ ipting oZLyfQs tme ile cDyWTQhWcbiQxb System zp Jpgjp Obj BxBlxl ect JTFXqcP ejfPx" ascii
    $s7  = "function xkavZ(xDQdwq) {" fullword ascii
    $s8  = "function VBFYDaQjD(YsYVXeZDNCf) {" fullword ascii
    $s9  = "if(d>=Z.length) {break;}" fullword ascii
    $s10 = "if (VwwDa > 172817-612){return true;} else {return false;}" fullword ascii
    $s11 = "return uOAzPtP(FS,fRkjI[882-876]+fRkjI[570-563]+fRkjI[581-573]);" fullword ascii
    $s12 = "function CwOV(VwwDa) {" fullword ascii
    $s13 = "function SfqKG(HwYyJv) {" fullword ascii
    $s14 = "function lQiGiLhz() {" fullword ascii
    $s15 = "return Sei.size;" fullword ascii
    $s16 = "function DlepR(bzj,VKCtC) {" fullword ascii
    $s17 = "function WEhb(WsQLy) {" fullword ascii
    $s18 = "return mHEx.responseBody;" fullword ascii
    $s19 = "return new ActiveXObject(HwYyJv);" fullword ascii
    $s20 = "return XUueB;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}