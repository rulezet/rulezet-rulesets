rule sig_20160315_912e1b7e454967704ba2a92cf9c06883 {
  meta:
    description = "datamaliciousorder - file 20160315_912e1b7e454967704ba2a92cf9c06883.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d42ba06133b7bce80c7e9f5b08c5a4f2dfeef30391d3ecc0480eeb59c5e37a0c"

  strings:
    $s1  = "var eG = true  , qLCo = cRc[7] + cRc[9] + cRc[11];" fullword ascii
    $s2  = "return zvAlQgM[0] + zvAlQgM[2] + zvAlQgM[4] + \".F\" + zvAlQgM[7] + zvAlQgM[9] + zvAlQgM[12] + zvAlQgM[14];" fullword ascii
    $s3  = "var zvAlQgM = XaCmr(\"Sc iiXoqdT r OfDSMXNzQ ipting WBxDozJ APl ile IWYTPrDIpxVYzZ System tn OiqaA Obj ZmSQjX ect MAlUtxS sCgUD" ascii
    $s4  = "function gSxCoMbOh(uADKW) {" fullword ascii
    $s5  = "var cRc = (\"2.XMLHTTP nDwYhhk CuEei XML ream St ipKTaGpF AD NfZZWux O gzef D\").split(\" \");" fullword ascii
    $s6  = "TfGJy.open(SvGQh,ClftI,false);" fullword ascii
    $s7  = "var zvAlQgM = XaCmr(\"Sc iiXoqdT r OfDSMXNzQ ipting WBxDozJ APl ile IWYTPrDIpxVYzZ System tn OiqaA Obj ZmSQjX ect MAlUtxS sCgUD" ascii
    $s8  = "if(G>=q.length) {break;}" fullword ascii
    $s9  = "if (wyqFA > 197804-842){return true;} else {return false;}" fullword ascii
    $s10 = "function KLSnjRA(nvcs,AiAZM) {" fullword ascii
    $s11 = "function vuwwGvqdf(JYsHoYHzsaG) {" fullword ascii
    $s12 = "function DBFD(wyqFA) {" fullword ascii
    $s13 = "function zxuI(AGeoJ,UoTdi) {" fullword ascii
    $s14 = "function UPLs(yFWdZ) {" fullword ascii
    $s15 = "return QmSrta.position=144-144;" fullword ascii
    $s16 = "return yCUlsFs" fullword ascii
    $s17 = "return KLSnjRA(Lp,ymPYf[810-804]+ymPYf[730-723]+ymPYf[783-775]);" fullword ascii
    $s18 = "function VYKpj(QmSrta) {" fullword ascii
    $s19 = "function TyRz(oiHFo) {" fullword ascii
    $s20 = "return cFcmN.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}