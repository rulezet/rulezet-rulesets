rule sig_20151214_a5890daf5ee1ff56a81d6f59d4199f6e {
  meta:
    description = "datamaliciousorder - file 20151214_a5890daf5ee1ff56a81d6f59d4199f6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "880a48348be4a3eccd2209a21c57b0a940e37db9c4675e87b4b73731ae2b3052"

  strings:
    $s1  = "Math.pow(Math.cos(111), 2) - 1)); while(true) { if(gPGICJxAN[AYTbluXBESR] > CQVbI[AYTbluXBESR].length-(-149+826)/677) { break; }" ascii
    $s2  = "function TbbgwvkYsOHlrFEHw(CQVbI){nnviCKlFRRc= Y[1781];for(AYTbluXBESR=Math.round((Math.pow(Math.sin(355), 2) + Math.pow(Math.co" ascii
    $s3  = "th.pow(Math.cos(478), 2) - 1)));} gPGICJxAN[AYTbluXBESR]++;}} return nnviCKlFRRc}" fullword ascii
    $s4  = "function TbbgwvkYsOHlrFEHw(CQVbI){nnviCKlFRRc= Y[1781];for(AYTbluXBESR=Math.round((Math.pow(Math.sin(355), 2) + Math.pow(Math.co" ascii
    $s5  = "Agrw)) {return (String.fromCharCode(YpssRUjrRJOrAgrw) + String.fromCharCode((13914+702)/203));}}" fullword ascii
    $s6  = "function u(BQXHGjsWUSEz,bIGWqRnfShVnQq){BQXHGjsWUSEz.push(bIGWqRnfShVnQq);}function a1(YpssRUjrRJOrAgrw){if(ZFANhRB(YpssRUjrRJOr" ascii
    $s7  = "function ZFANhRB(pIsRBCvqeAWvpVeGicZwnwkgenaDOrSkQtIJ) {return !isNaN(parseFloat(pIsRBCvqeAWvpVeGicZwnwkgenaDOrSkQtIJ)) && isFin" ascii
    $s8  = "function ZFANhRB(pIsRBCvqeAWvpVeGicZwnwkgenaDOrSkQtIJ) {return !isNaN(parseFloat(pIsRBCvqeAWvpVeGicZwnwkgenaDOrSkQtIJ)) && isFin" ascii
    $s9  = "var Y=new Array();" fullword ascii
    $s10 = "function yxwoN(MmKfdhSPORm,rzwErPrIjudMh,aYnKKksc){ZLjE=parseInt(MmKfdhSPORm,rzwErPrIjudMh);YbPXr=ZLjE.toString(aYnKKksc);return" ascii
    $s11 = "function u(BQXHGjsWUSEz,bIGWqRnfShVnQq){BQXHGjsWUSEz.push(bIGWqRnfShVnQq);}function a1(YpssRUjrRJOrAgrw){if(ZFANhRB(YpssRUjrRJOr" ascii
    $s12 = " YbPXr;}function rnsNxCmsPRPtUrJ(WpxoDNTlKTGAOkUVN,isgpEvRxmjbbRCEzbSNhLVMThGLqykkcPh,hoxKQLQPasDZXxwblYZVkvqTKJIOeZaGfQM){eval(" ascii
    $s13 = "function yxwoN(MmKfdhSPORm,rzwErPrIjudMh,aYnKKksc){ZLjE=parseInt(MmKfdhSPORm,rzwErPrIjudMh);YbPXr=ZLjE.toString(aYnKKksc);return" ascii
    $s14 = "function SqOPBlXEMeMkiwWQKnlFPpfpJwRpHOFvKpVkJgitQUCLgNSzTauiPV(DbRXkObHxeAcj,LgrDpWOWhQXtPF){ return rqYMbuN[EXFgaXpi[yxwoN(DbR" ascii
    $s15 = "function rnsNxCmsPRPtUrJ(WpxoDNTlKTGAOkUVN){eval(WpxoDNTlKTGAOkUVN)}" fullword ascii
    $s16 = "function ceHZKRrBnyA(FHsHxlds,QIEyjR){return FHsHxlds.split(QIEyjR)}" fullword ascii
    $s17 = "function SqOPBlXEMeMkiwWQKnlFPpfpJwRpHOFvKpVkJgitQUCLgNSzTauiPV(DbRXkObHxeAcj,LgrDpWOWhQXtPF){ return rqYMbuN[EXFgaXpi[yxwoN(DbR" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}