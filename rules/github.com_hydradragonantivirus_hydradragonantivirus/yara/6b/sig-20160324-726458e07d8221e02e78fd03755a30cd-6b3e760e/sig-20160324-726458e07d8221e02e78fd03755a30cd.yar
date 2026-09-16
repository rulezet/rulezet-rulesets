rule sig_20160324_726458e07d8221e02e78fd03755a30cd {
  meta:
    description = "datamaliciousorder - file 20160324_726458e07d8221e02e78fd03755a30cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e176293df70535a7f8cd6830e5f20348bd2a3110cc3c623af92e7c1b85145387"

  strings:
    $s1  = "return WScript.CreateObject(IqXrN);" fullword ascii
    $s2  = "var yE = true  , JLkx = ZQx[7] + ZQx[9] + ZQx[11];" fullword ascii
    $s3  = "return aFGveEN[0] + aFGveEN[2] + aFGveEN[4] + \".F\" + aFGveEN[7] + aFGveEN[9] + aFGveEN[12] + aFGveEN[14];" fullword ascii
    $s4  = "lBaY.open(WSHAj,kBmuE,false);" fullword ascii
    $s5  = "var aFGveEN = YqqXM(UgpvfRRQOa+\" \"+\"System fJ MmcYX Obj TAYpwA ect HlLQCjO wVcxN\", \" \");" fullword ascii
    $s6  = "var ZQx = (\"2.XMLHTTP wQQbvKJ lHrNk XML ream St sbJfSvpu AD XSNBnfG O afjj D\").split(\" \");" fullword ascii
    $s7  = "function szCC(ebsBq) {" fullword ascii
    $s8  = "function mVkD(RseDJ,rpCZI) {" fullword ascii
    $s9  = "return DiV.size;" fullword ascii
    $s10 = "if (vZkHV > 196025-283){return true;} else {return false;}" fullword ascii
    $s11 = "return tnryQ;" fullword ascii
    $s12 = "if(g>=p.length) {break;}" fullword ascii
    $s13 = "var MfyMPMb = \"WmhQmZ*hNv*pt.S\"+\"hell*qqGQlKQ*Scri*\";" fullword ascii
    $s14 = "function TGqqQkH(FhKy,sbaNQ) {" fullword ascii
    $s15 = "mVu = g; break; " fullword ascii
    $s16 = "function ASgtaVBIP(RCRCY) {" fullword ascii
    $s17 = "function AAQt(wprDC) {" fullword ascii
    $s18 = "function wipgIrTU(DleN) {" fullword ascii
    $s19 = "return vTQGKu/*yUcre0bqAE77qvL7tDyEM9whq*/.position=937-937;" fullword ascii
    $s20 = "return Zqkf[XvxxKK[0]];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}