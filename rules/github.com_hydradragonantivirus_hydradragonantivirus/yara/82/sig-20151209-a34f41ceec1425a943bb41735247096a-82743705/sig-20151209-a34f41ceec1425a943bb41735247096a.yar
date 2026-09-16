rule sig_20151209_a34f41ceec1425a943bb41735247096a {
  meta:
    description = "datamaliciousorder - file 20151209_a34f41ceec1425a943bb41735247096a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db1d6c7f53940460f4948c1535ac88f8f1d41fbc860d7f12f9bdf05e5ee22fc5"

  strings:
    $s1  = "function sPSZAFl(RrcnqHDOKZMSrwdqUOafAUkJAxdoiwpfjZWw) {return !isNaN(parseFloat(RrcnqHDOKZMSrwdqUOafAUkJAxdoiwpfjZWw)) && isFin" ascii
    $s2  = "function sPSZAFl(RrcnqHDOKZMSrwdqUOafAUkJAxdoiwpfjZWw) {return !isNaN(parseFloat(RrcnqHDOKZMSrwdqUOafAUkJAxdoiwpfjZWw)) && isFin" ascii
    $s3  = "function Eqcdw(kvpUxPuLNBa,bAHsHevTKacSC,bopKKGey){IfPK=parseInt(kvpUxPuLNBa,bAHsHevTKacSC);BgUnl=IfPK.toString(bopKKGey);return" ascii
    $s4  = "} return skkGulSXziO}" fullword ascii
    $s5  = "function Eqcdw(kvpUxPuLNBa,bAHsHevTKacSC,bopKKGey){IfPK=parseInt(kvpUxPuLNBa,bAHsHevTKacSC);BgUnl=IfPK.toString(bopKKGey);return" ascii
    $s6  = "EnjfgzF[AWxqAGPGffl]=(-586+586)/171; while(true) { if(UpEnjfgzF[AWxqAGPGffl] > HqXQX[AWxqAGPGffl].length-(934+2)/936) { break; }" ascii
    $s7  = "function cKtcsZXOrjp(LtKHMsVK,DlAJir){return LtKHMsVK.split(DlAJir)}" fullword ascii
    $s8  = "function cvWjefBrlnpteoTRg(HqXQX){skkGulSXziO= '';for(AWxqAGPGffl=(-700+700)/197; AWxqAGPGffl < (429+61)/245; AWxqAGPGffl++) {Up" ascii
    $s9  = " BgUnl;}function emdMcGKqPyXjoya(ryXrQsLDiMavSubeK){eval(ryXrQsLDiMavSubeK)}" fullword ascii
    $s10 = "function cvWjefBrlnpteoTRg(HqXQX){skkGulSXziO= '';for(AWxqAGPGffl=(-700+700)/197; AWxqAGPGffl < (429+61)/245; AWxqAGPGffl++) {Up" ascii
    $s11 = "function pGtYnVPQCmNCteCAqevEPDXaMNIttzYhhDXbMrGalVhjGdTtzZproj(RRDivivPKqjkz,mOqpBSWlkleWHE){ return QXtor[Eqcdw(RRDivivPKqjkz[" ascii
    $s12 = "function pGtYnVPQCmNCteCAqevEPDXaMNIttzYhhDXbMrGalVhjGdTtzZproj(RRDivivPKqjkz,mOqpBSWlkleWHE){ return QXtor[Eqcdw(RRDivivPKqjkz[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}