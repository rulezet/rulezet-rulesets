rule sig_20151216_67d02abbc328c2cb9196232b9601d5e8 {
  meta:
    description = "datamaliciousorder - file 20151216_67d02abbc328c2cb9196232b9601d5e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f37c02e1509469a4a4255810bb798b92a9560ab8dacba4040506ddfd29ab3a98"

  strings:
    $s1  = ") - 1));while(true){if (cctqTuRTUBg >= (3238+770)/668){break;}JEwbdKXMt[cctqTuRTUBg]=Math.round((Math.pow(Math.sin(999), 2) + Ma" ascii
    $s2  = "(Math.cos(315), 2) - 1)));} JEwbdKXMt[cctqTuRTUBg]++;}cctqTuRTUBg++;} return KAFiPgAboia}" fullword ascii
    $s3  = "function GqzrMOHjVMTPJEaRo(AJtVa){KAFiPgAboia= '';cctqTuRTUBg=Math.round((Math.pow(Math.sin(868), 2) + Math.pow(Math.cos(868), 2" ascii
    $s4  = "th.pow(Math.cos(999), 2) - 1)); while(true) { if(JEwbdKXMt[cctqTuRTUBg] > AJtVa[cctqTuRTUBg].length-(145+84)/229) { break; } if " ascii
    $s5  = "function GqzrMOHjVMTPJEaRo(AJtVa){KAFiPgAboia= '';cctqTuRTUBg=Math.round((Math.pow(Math.sin(868), 2) + Math.pow(Math.cos(868), 2" ascii
    $s6  = "function bNsVYPI(leUzfcWMgEANeAkFCusJlIOPoyaAhepuNDBG) {return !wHvsIgCcFyq(NGGJsyVeBBzuYRb(leUzfcWMgEANeAkFCusJlIOPoyaAhepuNDBG" ascii
    $s7  = "function BrJxpgJkLsgQmOofq(LVjtmpGNeg,iyFlzcmUOF) {return parseInt(LVjtmpGNeg,iyFlzcmUOF);}" fullword ascii
    $s8  = "function KRZSPkaUvFusKSKLDDDDgwbeDnaoXypqsCtDxJeqZjVXkjCMqZYFVp(FgndNujTTeVpl,cTlHleNZaGGSLo){ return AIebVXI[QmOrdwKF[Dvpch(Fgn" ascii
    $s9  = "function NGGJsyVeBBzuYRb(zReUenEABzrSNYoBqoE) {return parseFloat(zReUenEABzrSNYoBqoE);}" fullword ascii
    $s10 = "function Dvpch(CdKfucCYSUK,EtzXMfNyedvWe,QRgscFlh){Kqeb=BrJxpgJkLsgQmOofq(CdKfucCYSUK,EtzXMfNyedvWe);wwVuk=Kqeb.toString(QRgscFl" ascii
    $s11 = "function bNsVYPI(leUzfcWMgEANeAkFCusJlIOPoyaAhepuNDBG) {return !wHvsIgCcFyq(NGGJsyVeBBzuYRb(leUzfcWMgEANeAkFCusJlIOPoyaAhepuNDBG" ascii
    $s12 = ",'P','F','M','z','W','7','a','*','u','x','X','y','9','e','+','{','!','Y','/','3','L','Z','k','M','[','<','`','B','+',' ',String." ascii
    $s13 = "function bSFQqVNNXCCKcIs(XMAmvdXqQHvmzteyQ,DWgvypmUltXxwneVfHtjqXsrPcTxitnVAH,qLzJlcGgAXQjnlRzjqmCrSWtyeLeBkPkaPA){eval(XMAmvdXq" ascii
    $s14 = "function n(FzKfoZeQoLwT,ujFCdOtDNxIMdF){FzKfoZeQoLwT.push(ujFCdOtDNxIMdF);}" fullword ascii
    $s15 = "function bSFQqVNNXCCKcIs(XMAmvdXqQHvmzteyQ,DWgvypmUltXxwneVfHtjqXsrPcTxitnVAH,qLzJlcGgAXQjnlRzjqmCrSWtyeLeBkPkaPA){eval(XMAmvdXq" ascii
    $s16 = "function Dvpch(CdKfucCYSUK,EtzXMfNyedvWe,QRgscFlh){Kqeb=BrJxpgJkLsgQmOofq(CdKfucCYSUK,EtzXMfNyedvWe);wwVuk=Kqeb.toString(QRgscFl" ascii
    $s17 = "function JliOitKGUeBB(RMlgBmUnILVnY) {return isFinite(RMlgBmUnILVnY);}" fullword ascii
    $s18 = "function KRZSPkaUvFusKSKLDDDDgwbeDnaoXypqsCtDxJeqZjVXkjCMqZYFVp(FgndNujTTeVpl,cTlHleNZaGGSLo){ return AIebVXI[QmOrdwKF[Dvpch(Fgn" ascii
    $s19 = "h);return wwVuk;}" fullword ascii
    $s20 = "function T(GlCzRpFDACNYpH,IxtCMTPleqtDg,HBXRCRojZoI) {GlCzRpFDACNYpH[IxtCMTPleqtDg]=HBXRCRojZoI;}" fullword ascii

  condition:
    uint16(0) == 0x6d51 and
    8 of them
}