rule sig_20160314_f9bef19f89510a2de194293665a77336 {
  meta:
    description = "datamaliciousorder - file 20160314_f9bef19f89510a2de194293665a77336.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa9a793d35e6a8ad07d2c12e6eb25050881ea0ddf9b2d8c14d0e17c31f2e9b6d"

  strings:
    $s1  = "var JR = true  , TjuL = WNV[7] + WNV[9] + WNV[11];" fullword ascii
    $s2  = "return KwNlgnU[0] + KwNlgnU[2] + KwNlgnU[4] + \".F\" + KwNlgnU[7] + KwNlgnU[9] + KwNlgnU[12] + KwNlgnU[14];" fullword ascii
    $s3  = "kKibU.open(PHIkv,YgJfN,false);" fullword ascii
    $s4  = "var WNV = (\"2.XMLHTTP eyJZxuC hdTOf XML ream St vfAukOoH AD SebkEmT O FuMq D\").split(\" \");" fullword ascii
    $s5  = "ZQo = D; break; " fullword ascii
    $s6  = "if (TuRNn == 538-338){return true;} else {return false;}" fullword ascii
    $s7  = "return wwgYn.status;" fullword ascii
    $s8  = "function EJpO(aRNwA) {" fullword ascii
    $s9  = "return HiBF.responseBody;" fullword ascii
    $s10 = "return Wzoco;" fullword ascii
    $s11 = "if(D>=B.length) {break;}" fullword ascii
    $s12 = "function VxwgyGXJq(CkCccwexJRH) {" fullword ascii
    $s13 = "return NuZO.ExpandEnvironmentStrings(hcizx);" fullword ascii
    $s14 = "function gqTX(ECcNl,NVjFS) {" fullword ascii
    $s15 = "function pCOGHVV(NuZO,hcizx) {" fullword ascii
    $s16 = "return VvS.split(flcfJ);" fullword ascii
    $s17 = "function wXSP(wwgYn) {" fullword ascii
    $s18 = "return gGUTPlF" fullword ascii
    $s19 = "if (z >= oESAK.length) {break;}" fullword ascii
    $s20 = "function mnzGD(amfOOt) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}