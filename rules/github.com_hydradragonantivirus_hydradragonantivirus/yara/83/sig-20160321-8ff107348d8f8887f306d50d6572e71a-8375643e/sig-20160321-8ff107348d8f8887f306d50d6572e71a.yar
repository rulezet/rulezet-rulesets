rule sig_20160321_8ff107348d8f8887f306d50d6572e71a {
  meta:
    description = "datamaliciousorder - file 20160321_8ff107348d8f8887f306d50d6572e71a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c5e2624a4b655f55f933c538ad258db3ffdc5da2aa7038254d87c39013fff0b"

  strings:
    $s1  = "return WScript.CreateObject(urzvY);" fullword ascii
    $s2  = "return LUlQDzg[0] + LUlQDzg[2] + LUlQDzg[4] + \".F\" + LUlQDzg[7] + LUlQDzg[9] + LUlQDzg[12] + LUlQDzg[14];" fullword ascii
    $s3  = "var rh = true  , xZMQ = olV[7] + olV[9] + olV[11];" fullword ascii
    $s4  = "adATv.open(gtbFn,lQLyY,false);" fullword ascii
    $s5  = "var LUlQDzg = izEvr(EVLBuLZRys+\" \"+\"System iz UFjqF Obj ZMouqa ect rfaSJxS UdRRe\", \" \");" fullword ascii
    $s6  = "var olV = (\"2.XMLHTTP vbNkAHK WajQO XML ream St ZqhPpmuF AD vLPniVU O Rfxq D\").split(\" \");" fullword ascii
    $s7  = "return wMU.split(TgVyR);" fullword ascii
    $s8  = "function ExWeeyt(xKqp) {" fullword ascii
    $s9  = "return EMxpP;" fullword ascii
    $s10 = "if (yDHTB > 168833-929){return true;} else {return false;}" fullword ascii
    $s11 = "function hdIUxNlar(uBtZy) {" fullword ascii
    $s12 = "function Lzxe(yDHTB) {" fullword ascii
    $s13 = "function QlXawJb(rYlZ,QzQVp) {" fullword ascii
    $s14 = "return new ActiveXObject(XYhptt);" fullword ascii
    $s15 = "function Gdvw(raOYI) {" fullword ascii
    $s16 = "function NhqdV(XYhptt) {" fullword ascii
    $s17 = "function IsXE(AlxWM) {" fullword ascii
    $s18 = "function DInOAqbL(VNf) {" fullword ascii
    $s19 = "function eFNz(fsBiu) {" fullword ascii
    $s20 = "function GbroT(SfasOv) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}