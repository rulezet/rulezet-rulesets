rule sig_20160309_9bdf9d3e637d29f5f03ad99121a558c4 {
  meta:
    description = "datamaliciousorder - file 20160309_9bdf9d3e637d29f5f03ad99121a558c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6eac13474f5f669c7200c4765950beef6bccd4e9b23e10db33eaa600d98db07a"

  strings:
    $s1  = "var py = true  , jfDS = mlc[7] + mlc[9] + mlc[11];" fullword ascii
    $s2  = "return yjuRCpj[0] + yjuRCpj[2] + yjuRCpj[4] + \".F\" + yjuRCpj[7] + yjuRCpj[9] + yjuRCpj[12] + yjuRCpj[14];" fullword ascii
    $s3  = "LxkRJ.open(yIXSt,hwkHt,false);" fullword ascii
    $s4  = "var mlc = (\"2.XMLHTTP cRYESHu zuYjI XML ream St zfaeWJty AD hxrezaG O XoyD D\").split(\" \");" fullword ascii
    $s5  = "var yjuRCpj = \"Sc ZGXTsQR r FwzsVpVym ipting xZQGbcT oll ile BehwoQjsUPUJkg System VB pGPwK Obj cUjLEK ect FHbBfPe\".split(\" " ascii
    $s6  = "function ZwftgwEzx(xJwaO,MZkaa,dikGL,MMOJ) {" fullword ascii
    $s7  = "function ZEVHnIAX() {" fullword ascii
    $s8  = "pRB = w; break; " fullword ascii
    $s9  = "function HHHhD(QaxZBJ) {" fullword ascii
    $s10 = "if (ZBVEe == 564-364){return true;} else {return false;}" fullword ascii
    $s11 = "function nwuSyaZJ(QNfDl,TgfrDx) {" fullword ascii
    $s12 = "function TYmO(Lesgz,IgjpF) {" fullword ascii
    $s13 = "function eBJS(ZBVEe) {" fullword ascii
    $s14 = "function zuYC(Luryi,qgPxU) {" fullword ascii
    $s15 = "function Gzmp(JYaVM) {" fullword ascii
    $s16 = "return ZczF.responseBody;" fullword ascii
    $s17 = "function EFfAquJrQ(zsrSJabsNkV) {" fullword ascii
    $s18 = "function IPJVxPI(BirT,RRUKm) {" fullword ascii
    $s19 = "function jMUI(NBKrK) {" fullword ascii
    $s20 = "return IPJVxPI(zj,FBjya[890-884]+FBjya[775-768]+FBjya[127-119]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}