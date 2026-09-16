rule sig_20160324_771602c44987e3604ec8acd8577c802f {
  meta:
    description = "datamaliciousorder - file 20160324_771602c44987e3604ec8acd8577c802f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b47c7562f1a36f520ca06a825ffbe578d97378ef098ee8f036fcd13e9fe65fc4"

  strings:
    $s1  = "return WScript.CreateObject(BZuoz);" fullword ascii
    $s2  = "var Qo = true  , Chuu = Fmj[7] + Fmj[9] + Fmj[11];" fullword ascii
    $s3  = "return NCGXjFl[0] + NCGXjFl[2] + NCGXjFl[4] + \".F\" + NCGXjFl[7] + NCGXjFl[9] + NCGXjFl[12] + NCGXjFl[14];" fullword ascii
    $s4  = "EdwB.open(fmUjT,hiDvQ,false);" fullword ascii
    $s5  = "var Fmj = (\"2.XMLHTTP CjPbIxS sOKXl XML ream St SyjFwHCW AD ywOSlNv O OCym D\").split(\" \");" fullword ascii
    $s6  = "var NCGXjFl = BpRGI(KLFsAILnbu+\" \"+\"System kw tspst Obj OIxgzc ect LnEEOEa RDLQj\", \" \");" fullword ascii
    $s7  = "return vRUFN.status;" fullword ascii
    $s8  = "function qWxRt(GfhCnn) {" fullword ascii
    $s9  = "function BKFM(QLsGk) {" fullword ascii
    $s10 = "function lSim(xzRyL,hiDvQ,fmUjT) {" fullword ascii
    $s11 = "if (QLsGk > 180732-997){return true;} else {return false;}" fullword ascii
    $s12 = "return seix[NsofXC[0]];" fullword ascii
    $s13 = "NYh = x; break; " fullword ascii
    $s14 = "function TIBY(FiNHf,CUOWV) {" fullword ascii
    $s15 = "return VoLVPhg(TD,RglTx[154-148]+RglTx[259-252]+RglTx[860-852]);" fullword ascii
    $s16 = "function meLPZLqx(cru) {" fullword ascii
    $s17 = "function eXHR(BZuoz) {" fullword ascii
    $s18 = "function MfIkNEvfo(XvirIiBuKbI) {" fullword ascii
    $s19 = "return KqbTS;" fullword ascii
    $s20 = "function cVpp(KiGFv) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}