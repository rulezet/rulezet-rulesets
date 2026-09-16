rule sig_20160405_a9a3c8657595fc034261b2a29c4a244b {
  meta:
    description = "datamaliciousorder - file 20160405_a9a3c8657595fc034261b2a29c4a244b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef0e6fb2d505cf581ba1541aacf6bab86357c7f0e7eeb85721363d6e49cba1b3"

  strings:
    $s1  = "var XG = true  , PEfR = odJ[7] + odJ[9] + odJ[11];" fullword ascii
    $s2  = "return OkzTUPs[0] + OkzTUPs[2] + OkzTUPs[4] + \".F\" + OkzTUPs[7] + OkzTUPs[9] + OkzTUPs[12] + OkzTUPs[14];" fullword ascii
    $s3  = "qLWU.open(LDCXv,oSpfG,false);" fullword ascii
    $s4  = "var odJ = (\"2.XMLHTTP GESoJkU UzpNj XML ream St yfwijaAO AD gaXLUyE O ehrk D\").split(\" \");" fullword ascii
    $s5  = "function AwDPB(atVEqhnR,QYhf) {" fullword ascii
    $s6  = "function huYQXyd(OPTQ,kYLDv) {" fullword ascii
    $s7  = "function EpaX(sRRll) {" fullword ascii
    $s8  = "function dpts(zczaV) {" fullword ascii
    $s9  = "return \"xahMjZizGrdseJ\";" fullword ascii
    $s10 = "function CYdwDMBL(wXke) {" fullword ascii
    $s11 = "return fMv.size;" fullword ascii
    $s12 = "return sHoM;" fullword ascii
    $s13 = "var MYwfXeK = \"qFTHlz*xDO*pt.S\"+\"hell*uCnQCYc*Scri*\";" fullword ascii
    $s14 = "return tppTu;" fullword ascii
    $s15 = "function Kogq(HrDsY,oSpfG,LDCXv) {" fullword ascii
    $s16 = "return UneP[GSQwGO[0]];" fullword ascii
    $s17 = "if (B >= Sdrjx.length) {break;}" fullword ascii
    $s18 = "function TcpFJ(YrbPzv) {" fullword ascii
    $s19 = "return AacQizN;" fullword ascii
    $s20 = "function KTYydxWFN(XphuG) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}