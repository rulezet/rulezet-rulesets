rule sig_20160405_b9211d697cc5edab12b435310818c3b9 {
  meta:
    description = "datamaliciousorder - file 20160405_b9211d697cc5edab12b435310818c3b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad86240a5cd05b20e50fbca17df414813bf81682e1817b003f21d9115096abbd"

  strings:
    $s1  = "var Qc = true  , Iqfj = hTd[7] + hTd[9] + hTd[11];" fullword ascii
    $s2  = "return dYVtFrT[0] + dYVtFrT[2] + dYVtFrT[4] + \".F\" + dYVtFrT[7] + dYVtFrT[9] + dYVtFrT[12] + dYVtFrT[14];" fullword ascii
    $s3  = "var hTd = (\"2.XMLHTTP sXDtblv ykpTN XML ream St ODOAwqeN AD vjmRIZg O ghWy D\").split(\" \");" fullword ascii
    $s4  = "ijsa.open(XfWtD,RQOyc,false);" fullword ascii
    $s5  = "if(p>=l.length) {break;}" fullword ascii
    $s6  = "RQp = p; break; " fullword ascii
    $s7  = "return \"ljcKSJbaWKYuSl\";" fullword ascii
    $s8  = "function NCxw(qcxUO,mRNsv) {" fullword ascii
    $s9  = "var CE = riot(QK).split(\" \");" fullword ascii
    $s10 = "return clTCE;" fullword ascii
    $s11 = "function OswRQCW(NPnJ) {" fullword ascii
    $s12 = "function tACH(OBXIg) {" fullword ascii
    $s13 = "function gGgPUY(bukWgER) {" fullword ascii
    $s14 = "return NPnJ[aAjrIO[0]];" fullword ascii
    $s15 = "function DHHh(kMflA) {" fullword ascii
    $s16 = "var KtRdCWT = \"vnrIkn*DVv*pt.S\"+\"hell*RXNsAGV*Scri*\";" fullword ascii
    $s17 = "tACH(XVM); XVM.type = 1; NCxw(XVM,OswRQCW(TL)); if (JuEw(kBooOyns(XVM)))  {" fullword ascii
    $s18 = "function kBooOyns(EZb) {" fullword ascii
    $s19 = "if (O >= uYoKG.length) {break;}" fullword ascii
    $s20 = "return wtvaGGF[0];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}