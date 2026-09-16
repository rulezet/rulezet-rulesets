rule sig_20160526_7b15612800cbbfe7cee371532fa6b8b8 {
  meta:
    description = "datamaliciousorder - file 20160526_7b15612800cbbfe7cee371532fa6b8b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dab2d7860bccf82f858f91a5ce4f40db8ca6f42cbbb328f42d47cf658987f790"

  strings:
    $s1  = "Math.pow(Math.cos(209), 2) - 1))-443) | KYrVRoCdJrTXCgXXgUwXwwN<< (972 + Math.round((Math.pow(Math.sin(467), 2) + Math.pow(Math." ascii
    $s2  = ", 2) - 1))-424) & 0xff;OJMiJUQaRooJbRF = MaZMBVBxfBxqyGnrsrzZRX>> (529 + Math.round((Math.pow(Math.sin(862), 2) + Math.pow(Math." ascii
    $s3  = "sin(64), 2) + Math.pow(Math.cos(64), 2) - 1))-5)) GGSYES += Ge(wNbPXRdTLVuPxPUmohRTE);else if (SNSQqCs == (82 + Math.round((Math" ascii
    $s4  = "cos(862), 2) - 1))-521) & 0xff;JvytGNbzWjrB = MaZMBVBxfBxqyGnrsrzZRX & 0xff;if (OtigaJnXesKo == (69 + Math.round((Math.pow(Math." ascii
    $s5  = "function jQCEhTfzWS(wLVOxNpQsGfIe) {var WMHeFRNKeN = cZncKdOvoEXvRwI.join(prWJXVBFAFTvMwwfLDB[0]);var wNbPXRdTLVuPxPUmohRTE, OJM" ascii
    $s6  = "function gClkVglOTbVJNykGnkqy(AAVGfmGmlrZd,UpuGlcxtJ){return AAVGfmGmlrZd.charAt(UpuGlcxtJ);}" fullword ascii
    $s7  = "function Ge(fMnArNTTxvNlbjlSLciuc){return String.fromCharCode(fMnArNTTxvNlbjlSLciuc);}" fullword ascii
    $s8  = "function OmxgGaFMMd(wejHBQHmGCcYFPQ,XGLaedH){return wejHBQHmGCcYFPQ.indexOf(XGLaedH);}" fullword ascii
    $s9  = "function goncMzdTAr(qjInPmalfTGLVULT,rNAiJKbgZvtijozRnAFJY,kqSPaUONZB){return String.fromCharCode(qjInPmalfTGLVULT,rNAiJKbgZvtij" ascii
    $s10 = ";return GGSYES;}" fullword ascii
    $s11 = "function FKHDdPfDKbQRiOUYdZa(pJgUOnvK,YCVWAwrbyxpSFttbxnK){return String.fromCharCode(pJgUOnvK,YCVWAwrbyxpSFttbxnK);}" fullword ascii
    $s12 = "function jQCEhTfzWS(wLVOxNpQsGfIe) {var WMHeFRNKeN = cZncKdOvoEXvRwI.join(prWJXVBFAFTvMwwfLDB[0]);var wNbPXRdTLVuPxPUmohRTE, OJM" ascii
    $s13 = "function goncMzdTAr(qjInPmalfTGLVULT,rNAiJKbgZvtijozRnAFJY,kqSPaUONZB){return String.fromCharCode(qjInPmalfTGLVULT,rNAiJKbgZvtij" ascii
    $s14 = "bRF);else GGSYES += goncMzdTAr(wNbPXRdTLVuPxPUmohRTE, OJMiJUQaRooJbRF, JvytGNbzWjrB);} while (pUjVwDDQFB < wLVOxNpQsGfIe.length)" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}