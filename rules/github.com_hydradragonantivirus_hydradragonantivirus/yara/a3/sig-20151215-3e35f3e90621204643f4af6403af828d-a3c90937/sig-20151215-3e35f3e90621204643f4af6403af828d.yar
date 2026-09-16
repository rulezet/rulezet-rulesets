rule sig_20151215_3e35f3e90621204643f4af6403af828d {
  meta:
    description = "datamaliciousorder - file 20151215_3e35f3e90621204643f4af6403af828d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63bbd47930965a7e7934509f7f9195e4937c55eb64e7dc628c847a6d279b0132"

  strings:
    $s1  = "ath.pow(Math.cos(478), 2) - 1)); while(true) { if(KrTQPcHPt[QScWdpCAriX] > GMQfb[QScWdpCAriX].length-(126+264)/390) { break; } i" ascii
    $s2  = "pow(Math.cos(359), 2) - 1)));} KrTQPcHPt[QScWdpCAriX]++;}} return sFSkDslCoZB}" fullword ascii
    $s3  = "function gXDLhXYgavvNVdbxY(GMQfb){sFSkDslCoZB= s[1775];for(QScWdpCAriX=Math.round((Math.pow(Math.sin(840), 2) + Math.pow(Math.co" ascii
    $s4  = "function IfRtO(jSzcwELFmys,OPABynfpvFwyo,lIrKZcFC){CTQj=parseInt(jSzcwELFmys,OPABynfpvFwyo);simir=CTQj.toString(lIrKZcFC);return" ascii
    $s5  = " simir;}function SfIhcKgnmmeDdGX(eScvjwgRNzqICGIdh,wqrrIiDbdqOjAgzgqDOBpZzUcgchPmGcQu,FCqftpmMrAqEatomneqbxtubmDOuOdYAiGx){eval(" ascii
    $s6  = "NjzB)) {return (String.fromCharCode(cIqcsMkdjFCPNjzB) + String.fromCharCode((19923+953)/307));}}" fullword ascii
    $s7  = "function L(jczkXIVPoSjf,VLtdljXDFDLKWa){jczkXIVPoSjf.push(VLtdljXDFDLKWa);}function e3(cIqcsMkdjFCPNjzB){if(rwtnOSj(cIqcsMkdjFCP" ascii
    $s8  = "function rwtnOSj(pwXrjdKwjVcDZcBtmBfOShJOvdXJpurDSuTX) {return !isNaN(parseFloat(pwXrjdKwjVcDZcBtmBfOShJOvdXJpurDSuTX)) && isFin" ascii
    $s9  = "function gXDLhXYgavvNVdbxY(GMQfb){sFSkDslCoZB= s[1775];for(QScWdpCAriX=Math.round((Math.pow(Math.sin(840), 2) + Math.pow(Math.co" ascii
    $s10 = "ssflEgqGmfeMoAJcoduGZkMZRSosPWBGenw([GMQfb[QScWdpCAriX][KrTQPcHPt[QScWdpCAriX]]], Math.round((Math.pow(Math.sin(359), 2) + Math." ascii
    $s11 = "function rwtnOSj(pwXrjdKwjVcDZcBtmBfOShJOvdXJpurDSuTX) {return !isNaN(parseFloat(pwXrjdKwjVcDZcBtmBfOShJOvdXJpurDSuTX)) && isFin" ascii
    $s12 = "var s=new Array();" fullword ascii
    $s13 = "function mQGsbCgDIZGedUswtBLssflEgqGmfeMoAJcoduGZkMZRSosPWBGenw(oHMgodVxWPyIf,hJJRLkwnWuglJb){ return VgeRBhd[wVJsoixt[IfRtO(oHM" ascii
    $s14 = "function L(jczkXIVPoSjf,VLtdljXDFDLKWa){jczkXIVPoSjf.push(VLtdljXDFDLKWa);}function e3(cIqcsMkdjFCPNjzB){if(rwtnOSj(cIqcsMkdjFCP" ascii
    $s15 = "function IfRtO(jSzcwELFmys,OPABynfpvFwyo,lIrKZcFC){CTQj=parseInt(jSzcwELFmys,OPABynfpvFwyo);simir=CTQj.toString(lIrKZcFC);return" ascii
    $s16 = "function SfIhcKgnmmeDdGX(eScvjwgRNzqICGIdh){eval(eScvjwgRNzqICGIdh)}" fullword ascii
    $s17 = "function gyWFZeVZcQM(bGhwmOKj,zEhEsK){return bGhwmOKj.split(zEhEsK)}" fullword ascii
    $s18 = "function mQGsbCgDIZGedUswtBLssflEgqGmfeMoAJcoduGZkMZRSosPWBGenw(oHMgodVxWPyIf,hJJRLkwnWuglJb){ return VgeRBhd[wVJsoixt[IfRtO(oHM" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}