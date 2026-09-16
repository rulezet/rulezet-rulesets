rule sig_20151210_f941fbb3bdf0d323fd97b18bea5e16b9 {
  meta:
    description = "datamaliciousorder - file 20151210_f941fbb3bdf0d323fd97b18bea5e16b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c12555fdccf28962a62332b69bd313707541d02c7861d13faf97168b3c2e2648"

  strings:
    $s1  = "function fOnzKEv(TicpdbJbnhthStDtvSuMznScIUDWFAfGmAxy) {return !isNaN(parseFloat(TicpdbJbnhthStDtvSuMznScIUDWFAfGmAxy)) && isFin" ascii
    $s2  = "function fOnzKEv(TicpdbJbnhthStDtvSuMznScIUDWFAfGmAxy) {return !isNaN(parseFloat(TicpdbJbnhthStDtvSuMznScIUDWFAfGmAxy)) && isFin" ascii
    $s3  = "function zwqIiTJHQup(UYPcmkSC,pznnLh){return UYPcmkSC.split(pznnLh)}" fullword ascii
    $s4  = "function UAgCn(byrMbTvWiaG,VzeBoZyvlXmgB,qTEuYHdZ){hfHP=parseInt(byrMbTvWiaG,VzeBoZyvlXmgB);ZUuQZ=hfHP.toString(qTEuYHdZ);return" ascii
    $s5  = "AcOAawu=(-468+468)/887;while(true){if(AcOAawu>=(44801+383)/353){break;}aGtiuiZdoyyUC[AcOAawu]=String.fromCharCode(AcOAawu);AcOAa" ascii
    $s6  = "function jaANhKEzbucSwVLEVpiyUyjeuTdntfRXljidcuysFXNmcKAeYKsnFF(MtMVTVcxGrNJf,NAPtKrYmhuTgPT){ return aGtiuiZdoyyUC[UAgCn(MtMVTV" ascii
    $s7  = "function SIQDTCOYVllNaIVAd(sOvCe){nApvMmyDPFU= '';for(bOpXKucvtTk=(-243+243)/668; bOpXKucvtTk < (1377+123)/750; bOpXKucvtTk++) {" ascii
    $s8  = "function UAgCn(byrMbTvWiaG,VzeBoZyvlXmgB,qTEuYHdZ){hfHP=parseInt(byrMbTvWiaG,VzeBoZyvlXmgB);ZUuQZ=hfHP.toString(qTEuYHdZ);return" ascii
    $s9  = "AcOAawu=(-468+468)/887;while(true){if(AcOAawu>=(44801+383)/353){break;}aGtiuiZdoyyUC[AcOAawu]=String.fromCharCode(AcOAawu);AcOAa" ascii
    $s10 = "++;}} return nApvMmyDPFU}" fullword ascii
    $s11 = "function SIQDTCOYVllNaIVAd(sOvCe){nApvMmyDPFU= '';for(bOpXKucvtTk=(-243+243)/668; bOpXKucvtTk < (1377+123)/750; bOpXKucvtTk++) {" ascii
    $s12 = " ZUuQZ;}function fpFgPLYzFHJGBda(ObtFDBgYEvIENQsnP){eval(ObtFDBgYEvIENQsnP)}" fullword ascii
    $s13 = "function jaANhKEzbucSwVLEVpiyUyjeuTdntfRXljidcuysFXNmcKAeYKsnFF(MtMVTVcxGrNJf,NAPtKrYmhuTgPT){ return aGtiuiZdoyyUC[UAgCn(MtMVTV" ascii
    $s14 = "MCgUOFqfZ[bOpXKucvtTk]=(-536+536)/959; while(true) { if(MCgUOFqfZ[bOpXKucvtTk] > sOvCe[bOpXKucvtTk].length-(-31+286)/255) { brea" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}