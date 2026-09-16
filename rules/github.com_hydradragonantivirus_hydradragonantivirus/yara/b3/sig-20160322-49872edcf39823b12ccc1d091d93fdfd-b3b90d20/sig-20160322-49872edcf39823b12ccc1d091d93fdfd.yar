rule sig_20160322_49872edcf39823b12ccc1d091d93fdfd {
  meta:
    description = "datamaliciousorder - file 20160322_49872edcf39823b12ccc1d091d93fdfd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed8dd1f40ffc37df13bc7c048ffb928afd58ee8c2cc240ab914b8ac47be27e31"

  strings:
    $s1  = "return WScript.CreateObject(JnipK);" fullword ascii
    $s2  = "return CVMnOSL[0] + CVMnOSL[2] + CVMnOSL[4] + \".F\" + CVMnOSL[7] + CVMnOSL[9] + CVMnOSL[12] + CVMnOSL[14];" fullword ascii
    $s3  = "var rv = true  , BxLU = sbo[7] + sbo[9] + sbo[11];" fullword ascii
    $s4  = "var CVMnOSL = amRtM(DflwHHEKFz+\" \"+\"System EG igpNw Obj bCgjAU ect CbezbcO KGiVY\", \" \");" fullword ascii
    $s5  = "var sbo = (\"2.XMLHTTP bujjwkc DUMXS XML ream St ExPcNBXK AD CPQEblm O nLgm D\").split(\" \");" fullword ascii
    $s6  = "yKlO.open(IgJds,YLTfk,false);" fullword ascii
    $s7  = "function cTmQ(fUhXS) {" fullword ascii
    $s8  = "return mLk.split(SEasC);" fullword ascii
    $s9  = "function swij(FeDpp) {" fullword ascii
    $s10 = "function oAkn(nHkoy) {" fullword ascii
    $s11 = "return noSj[zHVyis[0]];" fullword ascii
    $s12 = "function SuSA(cPmTs) {" fullword ascii
    $s13 = "function zxOu(JnipK) {" fullword ascii
    $s14 = "if (o >= cPmTs.length) {break;}" fullword ascii
    $s15 = "return duMiw.status;" fullword ascii
    $s16 = "return tjYhRgI(BP,XKzaC[442-436]+XKzaC[929-922]+XKzaC[975-967]);" fullword ascii
    $s17 = "if (FeDpp == 978-778){return true;} else {return false;}" fullword ascii
    $s18 = "return wxPBE;" fullword ascii
    $s19 = "var uBdmKTbl = amRtM(\"bOAt@Ws@STfsRdS@c@XadEwU@ri\"+\"@pt@sumyiIbk@.S@EOtgH@he@lfMqKJ@ll@tfivjHE@iKCfdneC@hQYR\", \"@\");" fullword ascii
    $s20 = "return IkcyJX.position=707-707;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}