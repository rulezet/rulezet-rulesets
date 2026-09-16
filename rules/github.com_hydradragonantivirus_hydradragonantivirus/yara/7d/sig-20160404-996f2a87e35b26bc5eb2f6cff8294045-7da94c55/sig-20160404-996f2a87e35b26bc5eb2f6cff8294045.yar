rule sig_20160404_996f2a87e35b26bc5eb2f6cff8294045 {
  meta:
    description = "datamaliciousorder - file 20160404_996f2a87e35b26bc5eb2f6cff8294045.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f25e51b2b760798f253d55a8817773b45d3b14a4165cfaa6b719eeef1897d1ca"

  strings:
    $s1  = "var Th = true  , SYSt = pSD[7] + pSD[9] + pSD[11];" fullword ascii
    $s2  = "return zOCkzkQ[0] + zOCkzkQ[2] + zOCkzkQ[4] + \".F\" + zOCkzkQ[7] + zOCkzkQ[9] + zOCkzkQ[12] + zOCkzkQ[14];" fullword ascii
    $s3  = "var zOCkzkQ = EhONb(DruurXHXhQ+\" \"+\"System bF PJfKT Obj xVclcO ect BjcZaum pdoBn\", \" \");" fullword ascii
    $s4  = "var pSD = (\"2.XMLHTTP IcTTSeV jOpIv XML ream St wUGpBwlJ AD zpdaHay O Srah D\").split(\" \");" fullword ascii
    $s5  = "uERZ.open(INpkt,YfvHe,false);" fullword ascii
    $s6  = "function oIwb(fXAcJ) {" fullword ascii
    $s7  = "function xVUd(VMxAU) {" fullword ascii
    $s8  = "return new ActiveXObject(pZej);" fullword ascii
    $s9  = "function JonDRYv(jpRL,FKmRj) {" fullword ascii
    $s10 = "if (OOFlP > 187116-793){return true;} else {return false;}" fullword ascii
    $s11 = "return ouRe[plTLiq[0]];" fullword ascii
    $s12 = "if (FgSeE == 1035-835){return true;} else {return false;}" fullword ascii
    $s13 = "var cUesvNt = \"zcOpol*Uxv*pt.S\"+\"hell*euZykeJ*Scri*\";" fullword ascii
    $s14 = "return kgYxI;" fullword ascii
    $s15 = "function EhONb(Frm,tFTaC) {" fullword ascii
    $s16 = "function eVFSJ(qhTwUqsW,akgV) {" fullword ascii
    $s17 = "function DrVu(ckTln,VRAEw) {" fullword ascii
    $s18 = "return fQmwtFF;" fullword ascii
    $s19 = "function NKwH(STPYy,Nsnam) {" fullword ascii
    $s20 = "ixn = h; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}