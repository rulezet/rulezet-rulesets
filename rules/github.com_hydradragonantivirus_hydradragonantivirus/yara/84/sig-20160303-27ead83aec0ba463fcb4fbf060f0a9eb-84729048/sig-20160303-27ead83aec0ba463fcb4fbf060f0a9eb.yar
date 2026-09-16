rule sig_20160303_27ead83aec0ba463fcb4fbf060f0a9eb {
  meta:
    description = "datamaliciousorder - file 20160303_27ead83aec0ba463fcb4fbf060f0a9eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f52a6f27e1f7ab01a47459de072e4341ee73b7b4684e504d9fe496cdb66c8d84"

  strings:
    $s1  = "var eiQif = \"sHcvqR rJx pt.Shell hkMSBKr Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "return DwqWMJs[0] + DwqWMJs[2] + DwqWMJs[4] + \".F\" + DwqWMJs[7] + DwqWMJs[9] + DwqWMJs[12] + DwqWMJs[14];" fullword ascii
    $s3  = "var yb = true  , RibR = dpe[7] + \"\" + dpe[9];" fullword ascii
    $s4  = "var dpe = (iWA + \"TTP\" + \" lAZaBVA vAJrz XML ream St pOinFqmB AD phqPIbL OD\").split(\" \");" fullword ascii
    $s5  = "iHAgJ.open(ASgKw,icTPs,false);" fullword ascii
    $s6  = "var DwqWMJs = \"Sc OTakGhw r bkkcEpFNE ipting lPQpmOY xSJ ile PlrajeHeWMsDLR System qm onaAM Obj njlCYI ect FwwiVeT\".split(\" " ascii
    $s7  = "function SiNDARVuQ(pRmOS,nuCjk,zLLdr) {" fullword ascii
    $s8  = "return PI.ExpandEnvironmentStrings(eiQif[6]);" fullword ascii
    $s9  = "if (DcKHL == 774-574){return true;} else {return false;}" fullword ascii
    $s10 = "return zAIPB;" fullword ascii
    $s11 = "return HHlI.responseBody;" fullword ascii
    $s12 = "function fLCY(AltDQ) {" fullword ascii
    $s13 = "function ObzJr(fWzTKt) {" fullword ascii
    $s14 = "function SUhmmoIVI(xYiKerBhlZa) {" fullword ascii
    $s15 = "function ndiT(DcKHL) {" fullword ascii
    $s16 = "function DOzH(YjNvG) {" fullword ascii
    $s17 = "return bXkuFtO" fullword ascii
    $s18 = "function rpce(iHAgJ,icTPs,ASgKw) {" fullword ascii
    $s19 = "return new ActiveXObject(fWzTKt);" fullword ascii
    $s20 = "function afdkaVS(voLS) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}