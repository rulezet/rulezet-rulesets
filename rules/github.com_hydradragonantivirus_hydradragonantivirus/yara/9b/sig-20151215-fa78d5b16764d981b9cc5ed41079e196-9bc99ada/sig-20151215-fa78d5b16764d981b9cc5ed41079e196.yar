rule sig_20151215_fa78d5b16764d981b9cc5ed41079e196 {
  meta:
    description = "datamaliciousorder - file 20151215_fa78d5b16764d981b9cc5ed41079e196.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efd168a2176cbdac1f4b399303c04a7262d6f79d5b367525ee10011454029da6"

  strings:
    $s1  = "Math.pow(Math.cos(577), 2) - 1)); while(true) { if(CsxpbvflM[AGCwxHgxPvE] > cfiGZ[AGCwxHgxPvE].length-(-480+667)/187) { break; }" ascii
    $s2  = "function DVAHyKflPttYnMCEi(cfiGZ){OfBLjjuGwAC= s[1812];for(AGCwxHgxPvE=Math.round((Math.pow(Math.sin(681), 2) + Math.pow(Math.co" ascii
    $s3  = "h.pow(Math.cos(779), 2) - 1)));} CsxpbvflM[AGCwxHgxPvE]++;}} return OfBLjjuGwAC}" fullword ascii
    $s4  = "function DVAHyKflPttYnMCEi(cfiGZ){OfBLjjuGwAC= s[1812];for(AGCwxHgxPvE=Math.round((Math.pow(Math.sin(681), 2) + Math.pow(Math.co" ascii
    $s5  = "fnEk)) {return (String.fromCharCode(jnMgwBtUWwIefnEk) + String.fromCharCode((41027+699)/673));}}" fullword ascii
    $s6  = "function u(LmQDPNYNtEuv,jTZXmEFPZamJhM){LmQDPNYNtEuv.push(jTZXmEFPZamJhM);}function U0(jnMgwBtUWwIefnEk){if(XETXdHX(jnMgwBtUWwIe" ascii
    $s7  = "function XETXdHX(cLNnGhNWyXfyGEuPdAvcSmqGKQYOVbLRylzg) {return !isNaN(parseFloat(cLNnGhNWyXfyGEuPdAvcSmqGKQYOVbLRylzg)) && isFin" ascii
    $s8  = "function XETXdHX(cLNnGhNWyXfyGEuPdAvcSmqGKQYOVbLRylzg) {return !isNaN(parseFloat(cLNnGhNWyXfyGEuPdAvcSmqGKQYOVbLRylzg)) && isFin" ascii
    $s9  = "var s=new Array();" fullword ascii
    $s10 = "function zZVOUquclaKYmWMRYcBvfoWqAvNPssnKnOCJKMPiKHJrKKrxJRwOIZ(ibxXJaNDZDxEv,TiNnDKNgZFfXlS){ return lsXjBXM[CPsaHxYd[ZSbeS(ibx" ascii
    $s11 = "function u(LmQDPNYNtEuv,jTZXmEFPZamJhM){LmQDPNYNtEuv.push(jTZXmEFPZamJhM);}function U0(jnMgwBtUWwIefnEk){if(XETXdHX(jnMgwBtUWwIe" ascii
    $s12 = "function zZVOUquclaKYmWMRYcBvfoWqAvNPssnKnOCJKMPiKHJrKKrxJRwOIZ(ibxXJaNDZDxEv,TiNnDKNgZFfXlS){ return lsXjBXM[CPsaHxYd[ZSbeS(ibx" ascii
    $s13 = "function xlCoHsQRSuWGCbZ(hORrwZfoJTtYKYxMn){eval(hORrwZfoJTtYKYxMn)}" fullword ascii
    $s14 = "function ZSbeS(XnnqPTCRBvy,QpzpftahfhQEV,oIfvNbRw){CvKg=parseInt(XnnqPTCRBvy,QpzpftahfhQEV);bRHWb=CvKg.toString(oIfvNbRw);return" ascii
    $s15 = "function ZSbeS(XnnqPTCRBvy,QpzpftahfhQEV,oIfvNbRw){CvKg=parseInt(XnnqPTCRBvy,QpzpftahfhQEV);bRHWb=CvKg.toString(oIfvNbRw);return" ascii
    $s16 = " bRHWb;}function xlCoHsQRSuWGCbZ(hORrwZfoJTtYKYxMn,WSUpLYDxzOSWkrBxHpLLJRXEOtUglLLbjs,ItJiRUUalssCaTxnDhjqflJtTTskRpRZXZl){eval(" ascii
    $s17 = "function OQCaBVlYHWg(WCTUyAZK,QXKNiX){return WCTUyAZK.split(QXKNiX)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}