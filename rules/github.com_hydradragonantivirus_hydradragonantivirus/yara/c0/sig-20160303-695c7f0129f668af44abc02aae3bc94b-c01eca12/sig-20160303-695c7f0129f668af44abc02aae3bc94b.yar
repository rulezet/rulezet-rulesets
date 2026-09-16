rule sig_20160303_695c7f0129f668af44abc02aae3bc94b {
  meta:
    description = "datamaliciousorder - file 20160303_695c7f0129f668af44abc02aae3bc94b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd8886624dc3a8dd79401d2da062526f0ddb39ba22d74dbc3d6df34761d2dfc5"

  strings:
    $s1  = "var Huuxo = \"TdxrwP DCr pt.Shell OIQZYSj Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "return xLgvSzG[0] + xLgvSzG[2] + xLgvSzG[4] + \".F\" + xLgvSzG[7] + xLgvSzG[9] + xLgvSzG[12] + xLgvSzG[14];" fullword ascii
    $s3  = "var ZKN = (jRR + \"TTP\" + \" rbpEBoP hYHKi XML ream St OzoRIPXT AD qfGhDhH OD\").split(\" \");" fullword ascii
    $s4  = "var Kh = true  , UFqY = ZKN[7] + \"\" + ZKN[9];" fullword ascii
    $s5  = "HGUmf.open(unTIc,tDYzV,false);" fullword ascii
    $s6  = "var xLgvSzG = \"Sc GGYjsgn r wqFUjrOqb ipting IHYGKfr Tug ile IOfdYyfvvtQiyS System DS UlfRm Obj zPUKYN ect kTSBlLV\".split(\" " ascii
    $s7  = "function mmlU(GeSuJ) {" fullword ascii
    $s8  = "function EbKH(HGUmf,tDYzV,unTIc) {" fullword ascii
    $s9  = "return GYbNj.status;" fullword ascii
    $s10 = "function vnqG(hdbPk,wGupv) {" fullword ascii
    $s11 = "function suRs(hMGTp) {" fullword ascii
    $s12 = "function BYVfwNlKw(ehTtOmYEyZw) {" fullword ascii
    $s13 = "function Hxse(KzJoR) {" fullword ascii
    $s14 = "function LLoH(cjMof,RZZyI) {" fullword ascii
    $s15 = "if (KzJoR > 182893-866){return true;} else {return false;}" fullword ascii
    $s16 = "function aMmnboA(CBbA) {" fullword ascii
    $s17 = "function IZGDRgvn() {" fullword ascii
    $s18 = "function EXQPf(oCFTbj) {" fullword ascii
    $s19 = "return new ActiveXObject(oCFTbj);" fullword ascii
    $s20 = "return PlqOhkz" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}