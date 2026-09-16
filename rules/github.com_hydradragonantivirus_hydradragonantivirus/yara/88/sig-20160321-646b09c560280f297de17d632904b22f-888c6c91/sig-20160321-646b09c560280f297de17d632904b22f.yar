rule sig_20160321_646b09c560280f297de17d632904b22f {
  meta:
    description = "datamaliciousorder - file 20160321_646b09c560280f297de17d632904b22f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c137226cfa4c6661603702ddcdc7cd33746669eeffe2f30ca0cad4d5288671d6"

  strings:
    $s1  = "return WScript.CreateObject(yjEWl);" fullword ascii
    $s2  = "var Xh = true  , xiMC = Mur[7] + Mur[9] + Mur[11];" fullword ascii
    $s3  = "return cSxwlSX[0] + cSxwlSX[2] + cSxwlSX[4] + \".F\" + cSxwlSX[7] + cSxwlSX[9] + cSxwlSX[12] + cSxwlSX[14];" fullword ascii
    $s4  = "var cSxwlSX = sdeAJ(ncyxLaawuO+\" \"+\"System wc rBYGk Obj PSaBOb ect oQfvKGX TgKpZ\", \" \");" fullword ascii
    $s5  = "uQnNo.open(kggov,QLxvr,false);" fullword ascii
    $s6  = "var Mur = (\"2.XMLHTTP yeKxZLd bMBOP XML ream St PVWXPMEX AD YSKOWsd O IgWG D\").split(\" \");" fullword ascii
    $s7  = "function cNKYt(AzqaDj) {" fullword ascii
    $s8  = "return OrARG;" fullword ascii
    $s9  = "return ACwy.ExpandEnvironmentStrings(EcsFN);" fullword ascii
    $s10 = "EEL = q; break; " fullword ascii
    $s11 = "function SaxFRrcC(CliZ) {" fullword ascii
    $s12 = "if(q>=C.length) {break;}" fullword ascii
    $s13 = "function TabYi(gpNsyA) {" fullword ascii
    $s14 = "return PAuh[RVRdlp[0]];" fullword ascii
    $s15 = "function kEIx(IHdFz) {" fullword ascii
    $s16 = "function sdeAJ(Igy,KkOuy) {" fullword ascii
    $s17 = "if (D >= tnrbo.length) {break;}" fullword ascii
    $s18 = "function ZruYsegvk(BsFAM) {" fullword ascii
    $s19 = "function cTxWcZbA(icO) {" fullword ascii
    $s20 = "return wKyhLiU(Sb,AaNIV[261-255]+AaNIV[595-588]+AaNIV[369-361]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}