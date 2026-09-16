rule sig_20160404_8003048f464fa05bc78ec72b4a769d41 {
  meta:
    description = "datamaliciousorder - file 20160404_8003048f464fa05bc78ec72b4a769d41.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01977320026af5c32dd0722602e33975c7e7fd7bdad323ed9cde3fb5362f7d12"

  strings:
    $s1  = "return WEzZdTj[0] + WEzZdTj[2] + WEzZdTj[4] + \".F\" + WEzZdTj[7] + WEzZdTj[9] + WEzZdTj[12] + WEzZdTj[14];" fullword ascii
    $s2  = "var Yr = true  , DYGQ = YOf[7] + YOf[9] + YOf[11];" fullword ascii
    $s3  = "var WEzZdTj = ELQYa(glZKzKWzce+\" \"+\"System jL QJeGj Obj ojPOEL ect KdgcYKK FVaSU\", \" \");" fullword ascii
    $s4  = "KqPB.open(CMCOp,wHYdh,false);" fullword ascii
    $s5  = "var YOf = (\"2.XMLHTTP BgzettL eetqK XML ream St OKkCNDOI AD HaGTJMV O riwJ D\").split(\" \");" fullword ascii
    $s6  = "function gapu(wUjtU,LAKlW) {" fullword ascii
    $s7  = "return xZJ.split(rHXME);" fullword ascii
    $s8  = "function dEoyw(CXEecyVT,pBQR) {" fullword ascii
    $s9  = "function euiFbYT(FtLL,hFyoP) {" fullword ascii
    $s10 = "function ZlLj(WzmKP) {" fullword ascii
    $s11 = "if (gDVEv > 151300-502){return true;} else {return false;}" fullword ascii
    $s12 = "function ELQYa(xZJ,rHXME) {" fullword ascii
    $s13 = "return QMVb[gXftdQ[0]];" fullword ascii
    $s14 = "function mkNeBakPJ(dbDYHEjQouj) {" fullword ascii
    $s15 = "var aUzHJDX = \"aKdefp*Tos*pt.S\"+\"hell*KlKAEQw*Scri*\";" fullword ascii
    $s16 = "function aPhgT(OJLdQm) {" fullword ascii
    $s17 = "return AOHLP;" fullword ascii
    $s18 = "return QQrMQxp;" fullword ascii
    $s19 = "YYl = h; break; " fullword ascii
    $s20 = "function XJTEIp(JtyhaUa) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}