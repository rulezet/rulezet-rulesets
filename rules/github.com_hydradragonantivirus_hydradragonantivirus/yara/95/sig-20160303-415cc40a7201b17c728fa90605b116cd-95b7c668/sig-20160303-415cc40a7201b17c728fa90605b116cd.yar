rule sig_20160303_415cc40a7201b17c728fa90605b116cd {
  meta:
    description = "datamaliciousorder - file 20160303_415cc40a7201b17c728fa90605b116cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a36f24092068baa5602a97052fb971718b47208bda7207eefab01f00b8e0ad5"

  strings:
    $s1  = "var urjWy = \"pZCWeE DxZ pt.Shell pKZOpdk Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "return IPSZWep[0] + IPSZWep[2] + IPSZWep[4] + \".F\" + IPSZWep[7] + IPSZWep[9] + IPSZWep[12] + IPSZWep[14];" fullword ascii
    $s3  = "var sJ = true  , TjQK = iNl[7] + \"\" + iNl[9];" fullword ascii
    $s4  = "var iNl = (NwT + \"TTP\" + \" NhCbovP DdRPu XML ream St UaVFvsZC AD FGnEleN OD\").split(\" \");" fullword ascii
    $s5  = "nEMlv.open(rjqyi,dwODC,false);" fullword ascii
    $s6  = "var IPSZWep = \"Sc DfWznJA r noUtzyfeU ipting BdJrNak FuD ile yRZebidiHbUwkR System aW HoTrs Obj ljxabP ect UwQzLRe\".split(\" " ascii
    $s7  = "function RnOe(zbHZZ) {" fullword ascii
    $s8  = "if (zbHZZ == 980-780){return true;} else {return false;}" fullword ascii
    $s9  = "return eJWZY.status;" fullword ascii
    $s10 = "if (((new Date())>0,7364085888)) {" fullword ascii
    $s11 = "function mCpP(tgEVL) {" fullword ascii
    $s12 = "return new ActiveXObject(AvBjbm);" fullword ascii
    $s13 = "function yAoh(YDNjT) {" fullword ascii
    $s14 = "function oNmJhDm(TOAX) {" fullword ascii
    $s15 = "return LeKrLUz" fullword ascii
    $s16 = "function CcCk(TeNGI) {" fullword ascii
    $s17 = "function KicG(nEMlv,dwODC,rjqyi) {" fullword ascii
    $s18 = "function jUXJN(AvBjbm) {" fullword ascii
    $s19 = "zQt = Q; break; " fullword ascii
    $s20 = "return QbxE.responseBody;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}