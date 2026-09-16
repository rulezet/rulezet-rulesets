rule sig_20160405_b764e90746d44d6647a81ebe35d6b5bc {
  meta:
    description = "datamaliciousorder - file 20160405_b764e90746d44d6647a81ebe35d6b5bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e6355882b91d2b7e7ec00e193e347d33715a26e72a9fedb512a7d05792d4369"

  strings:
    $s1  = "return boFoiyt[0] + boFoiyt[2] + boFoiyt[4] + \".F\" + boFoiyt[7] + boFoiyt[9] + boFoiyt[12] + boFoiyt[14];" fullword ascii
    $s2  = "var HF = true  , iRuT = pKW[7] + pKW[9] + pKW[11];" fullword ascii
    $s3  = "var pKW = (\"2.XMLHTTP PMhrzBH ZTlOZ XML ream St bypiBUbL AD CluVQlQ O ZfNF D\").split(\" \");" fullword ascii
    $s4  = "mnFu.open(QAQdg,dUgxN,false);" fullword ascii
    $s5  = "if(W>=Z.length) {break;}" fullword ascii
    $s6  = "return sOwc;" fullword ascii
    $s7  = "function peOS(FPjMx,dUgxN,QAQdg) {" fullword ascii
    $s8  = "function SycTEMsjJ(IjbRq) {" fullword ascii
    $s9  = "if (fyfnj == 721-521){return true;} else {return false;}" fullword ascii
    $s10 = "var CKQHBwJ = \"RPHwfk*wtp*pt.S\"+\"hell*BMrFOHp*Scri*\";" fullword ascii
    $s11 = "function DQgI(WvhaM,CMPWy) {" fullword ascii
    $s12 = "function RTyBHJ(UrsL,qsLQEN) {" fullword ascii
    $s13 = "return \"zJykWYyDGFyfYb\";" fullword ascii
    $s14 = "function UTCrepoaP(SUsiVsLJKwg) {" fullword ascii
    $s15 = "function ozqGHnm(KDAW,NSDPH) {" fullword ascii
    $s16 = "function mVII(ZKhAC) {" fullword ascii
    $s17 = "function sQKc(nSaZv,GhVbJ) {" fullword ascii
    $s18 = "function LDKPJ(TorhMH) {" fullword ascii
    $s19 = "if (L >= YivjP.length) {break;}" fullword ascii
    $s20 = "return sEzz[tpBdBl[0]];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}