rule sig_20151210_efdbb207be15063004e31aba02cd9c75 {
  meta:
    description = "datamaliciousorder - file 20151210_efdbb207be15063004e31aba02cd9c75.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "213c3cebb56d29ca97ec67e28f0e211654413a58350166e9aa0b73a6b96822fa"

  strings:
    $s1  = "function dquJkOn(FJAtxxnSNGsPXMQfJjlelbAMLSBgilroxDWc) {return !isNaN(parseFloat(FJAtxxnSNGsPXMQfJjlelbAMLSBgilroxDWc)) && isFin" ascii
    $s2  = "function dquJkOn(FJAtxxnSNGsPXMQfJjlelbAMLSBgilroxDWc) {return !isNaN(parseFloat(FJAtxxnSNGsPXMQfJjlelbAMLSBgilroxDWc)) && isFin" ascii
    $s3  = "JdyGpApG[rEFgWvVnEgk]=(-797+797)/9; while(true) { if(NJdyGpApG[rEFgWvVnEgk] > bGFOd[rEFgWvVnEgk].length-(172+120)/292) { break; " ascii
    $s4  = "function lCWNIZDFpBqezZXrEpRNrOHRHcVtzFeYmyfNtflmAAsgPoXDzYlzzO(JCBCnwHlYrCoi,SezzzdlUWUcdgt){ return CUFVfmeBEIJUo[KlcME(JCBCnw" ascii
    $s5  = " dPOrL;}function CRpILAIcLfhPKaz(jZCpiPAaeLxAMhzCD){eval(jZCpiPAaeLxAMhzCD)}" fullword ascii
    $s6  = "} return ZPQRgcodLyh}" fullword ascii
    $s7  = "function KlcME(XzuFLOmlCQQ,hMoOcsYuGRbmj,XeBtGHXi){fSMk=parseInt(XzuFLOmlCQQ,hMoOcsYuGRbmj);dPOrL=fSMk.toString(XeBtGHXi);return" ascii
    $s8  = "function wnHDemJsmrNsvQejR(bGFOd){ZPQRgcodLyh= '';for(rEFgWvVnEgk=(-480+480)/932; rEFgWvVnEgk < (691+595)/643; rEFgWvVnEgk++) {N" ascii
    $s9  = "function krkomiDzMCq(SPmgLrLY,hSaDQk){return SPmgLrLY.split(hSaDQk)}" fullword ascii
    $s10 = "function lCWNIZDFpBqezZXrEpRNrOHRHcVtzFeYmyfNtflmAAsgPoXDzYlzzO(JCBCnwHlYrCoi,SezzzdlUWUcdgt){ return CUFVfmeBEIJUo[KlcME(JCBCnw" ascii
    $s11 = "function KlcME(XzuFLOmlCQQ,hMoOcsYuGRbmj,XeBtGHXi){fSMk=parseInt(XzuFLOmlCQQ,hMoOcsYuGRbmj);dPOrL=fSMk.toString(XeBtGHXi);return" ascii
    $s12 = "KfEPYPf=(-472+472)/448;while(true){if(KfEPYPf>=(27400+632)/219){break;}CUFVfmeBEIJUo[KfEPYPf]=String.fromCharCode(KfEPYPf);KfEPY" ascii
    $s13 = "KfEPYPf=(-472+472)/448;while(true){if(KfEPYPf>=(27400+632)/219){break;}CUFVfmeBEIJUo[KfEPYPf]=String.fromCharCode(KfEPYPf);KfEPY" ascii
    $s14 = "function wnHDemJsmrNsvQejR(bGFOd){ZPQRgcodLyh= '';for(rEFgWvVnEgk=(-480+480)/932; rEFgWvVnEgk < (691+595)/643; rEFgWvVnEgk++) {N" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}