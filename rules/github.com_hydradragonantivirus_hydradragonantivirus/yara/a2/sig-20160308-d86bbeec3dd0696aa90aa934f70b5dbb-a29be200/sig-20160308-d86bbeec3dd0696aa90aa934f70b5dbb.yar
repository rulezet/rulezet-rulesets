rule sig_20160308_d86bbeec3dd0696aa90aa934f70b5dbb {
  meta:
    description = "datamaliciousorder - file 20160308_d86bbeec3dd0696aa90aa934f70b5dbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26a40d570b5cff1b5c643baa225626d29382a645d68b25bc0c32e799b9d5afb9"

  strings:
    $s1  = "var wwYgGKH = \"Sc qItZtvE r exwIDoQhX ipting DcZJujA Ewr ile PORTFUqDBYSweh System Bs FlpeI Obj mLVTDQ ect zTYSkXH\".split(\" " ascii
    $s2  = "return wwYgGKH[0] + wwYgGKH[2] + wwYgGKH[4] + \".F\" + wwYgGKH[7] + wwYgGKH[9] + wwYgGKH[12] + wwYgGKH[14];" fullword ascii
    $s3  = "var GD = true  , odah = fPk[7] + fPk[9] + fPk[11];" fullword ascii
    $s4  = "var fPk = (\"2.XMLHTTP VXpORqP AAUEB XML ream St FxDNLvCm AD fIoWBld O kIlE D\").split(\" \");" fullword ascii
    $s5  = "OmwIj.open(gwWXu,DFbkV,false);" fullword ascii
    $s6  = "function qjERTnT(IRvG) {" fullword ascii
    $s7  = "function CPMu(LrSkb,UEaUp) {" fullword ascii
    $s8  = "return ZJ.ExpandEnvironmentStrings(KiEEe[6]+KiEEe[7]+KiEEe[8]);" fullword ascii
    $s9  = "function AKGO(OmwIj,DFbkV,gwWXu) {" fullword ascii
    $s10 = "function PNrZbVDd() {" fullword ascii
    $s11 = "function TtrPxNvPT(JoKCXWHrdRS) {" fullword ascii
    $s12 = "function oguG(DVJvE) {" fullword ascii
    $s13 = "return tpBbN;" fullword ascii
    $s14 = "if (UpYIB == 385-185){return true;} else {return false;}" fullword ascii
    $s15 = "function YhiG(aaBTu) {" fullword ascii
    $s16 = "function XVMc(UpYIB) {" fullword ascii
    $s17 = "return new ActiveXObject(IQhWkj);" fullword ascii
    $s18 = "if (k >= xJeOY.length) {break;}" fullword ascii
    $s19 = "UEQ = X; break; " fullword ascii
    $s20 = "function yTvC(trqUU) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}