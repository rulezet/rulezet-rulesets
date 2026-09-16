rule sig_20160321_42e8893d117acbd8ecb0678308a16705 {
  meta:
    description = "datamaliciousorder - file 20160321_42e8893d117acbd8ecb0678308a16705.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ccf30b2309c023f17e316a1646484283e82d68d491b55e93cd00690c53c7b87"

  strings:
    $s1  = "return WScript.CreateObject(avBzd);" fullword ascii
    $s2  = "var ak = true  , SQIL = iPk[7] + iPk[9] + iPk[11];" fullword ascii
    $s3  = "return oanniYL[0] + oanniYL[2] + oanniYL[4] + \".F\" + oanniYL[7] + oanniYL[9] + oanniYL[12] + oanniYL[14];" fullword ascii
    $s4  = "var iPk = (\"2.XMLHTTP zQWQwmL wcSZU XML ream St VXgKrUOj AD NrnkTRP O KnmE D\").split(\" \");" fullword ascii
    $s5  = "var oanniYL = KUuwS(jioOnbWrjR+\" \"+\"System HL SZxwJ Obj hBqIiN ect elMJMzB WsiYM\", \" \");" fullword ascii
    $s6  = "YkZfd.open(vCSTu,qxbHA,false);" fullword ascii
    $s7  = "function VnCsI(zsKiGY) {" fullword ascii
    $s8  = "function EmQV(avBzd) {" fullword ascii
    $s9  = "function AtcT(tdxYS) {" fullword ascii
    $s10 = "return ZOg.split(OUtZI);" fullword ascii
    $s11 = "function VQjY(oLLUU) {" fullword ascii
    $s12 = "return xdZz.ExpandEnvironmentStrings(hmOjb);" fullword ascii
    $s13 = "function gVvjXtn(xdZz,hmOjb) {" fullword ascii
    $s14 = "return lQir[Xgbbno[0]];" fullword ascii
    $s15 = "if (fEmkq == 495-295){return true;} else {return false;}" fullword ascii
    $s16 = "function yasd(cQCzm) {" fullword ascii
    $s17 = "function cUpU(fEmkq) {" fullword ascii
    $s18 = "function aJAl(HxiaX) {" fullword ascii
    $s19 = "function zgsRDsd(lQir) {" fullword ascii
    $s20 = "return new ActiveXObject(rswqex);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}