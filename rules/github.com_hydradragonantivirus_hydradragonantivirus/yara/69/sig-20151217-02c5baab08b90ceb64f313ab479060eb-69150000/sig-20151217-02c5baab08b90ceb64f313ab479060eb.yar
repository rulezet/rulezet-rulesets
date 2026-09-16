rule sig_20151217_02c5baab08b90ceb64f313ab479060eb {
  meta:
    description = "datamaliciousorder - file 20151217_02c5baab08b90ceb64f313ab479060eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0855c3173c4646ddfa5b383f6fdd9fc393b9a91230a12910f2c8bb2b513fd80e"

  strings:
    $s1  = ") - 1));while(true){if (qhWpmjBWGIZ >= (-361+535)/29){break;}ueJDIoZex[qhWpmjBWGIZ]=Math.round((Math.pow(Math.sin(936), 2) + Mat" ascii
    $s2  = "(Math.cos(639), 2) - 1)));} ueJDIoZex[qhWpmjBWGIZ]++;}qhWpmjBWGIZ++;} return vkbudSyrxTa}" fullword ascii
    $s3  = "function XLOpNmdqyjizdROjr(ZKpeK){vkbudSyrxTa= '';qhWpmjBWGIZ=Math.round((Math.pow(Math.sin(892), 2) + Math.pow(Math.cos(892), 2" ascii
    $s4  = "h.pow(Math.cos(936), 2) - 1)); while(true) { if(ueJDIoZex[qhWpmjBWGIZ] > ZKpeK[qhWpmjBWGIZ].length-(-15+747)/732) { break; } if " ascii
    $s5  = "function XLOpNmdqyjizdROjr(ZKpeK){vkbudSyrxTa= '';qhWpmjBWGIZ=Math.round((Math.pow(Math.sin(892), 2) + Math.pow(Math.cos(892), 2" ascii
    $s6  = "function IzbkypK(TUvZYiRjCoIinifrOPNnJVFkZrJoReVyoLEN) {return !frVeddiJyYX(wHhRURyuGBxHozm(TUvZYiRjCoIinifrOPNnJVFkZrJoReVyoLEN" ascii
    $s7  = "function p(coyCFQqijTlT,GRrUNEVppVNDZl){coyCFQqijTlT.push(GRrUNEVppVNDZl);}" fullword ascii
    $s8  = "var A = new Array();A[0]=[];A[0][0]='d';A[0][1]='a';A[0][2]='d';A[0][3]='a';A[0][4]='46';A[0][5]='3d';A[0][6]='42';A[0][7]='14';" ascii
    $s9  = "function bQslxDBlkGboauObRZiuIuHjxTuPsYcMBaYFIexOyJpxsRejKIsgpQ(iGrQdaenqCXwz,nuPrzpvEtsATTY){ return GbfNynl[qYCssvsf[coUiV(iGr" ascii
    $s10 = "function vsDzQvEISjLbkIP(heHdlXzOogWYZpLUp,HJRiAEjnSVnYFNtvWVpFYYdVnXjskAIUnz,qbGWbAPwXQLQfsvbFsZQTxYsNZpILYLVXWE){eval(heHdlXzO" ascii
    $s11 = "function coUiV(yeCLPsBpHnQ,LtohFNWjJZUdC,mzLjIBLr){FxpQ=xwejwsvaiVNZrDNQU(yeCLPsBpHnQ,LtohFNWjJZUdC);MFjXN=FxpQ.toString(mzLjIBL" ascii
    $s12 = "r);return MFjXN;}" fullword ascii
    $s13 = "function xwejwsvaiVNZrDNQU(upCdmicBoI,ntcdffaDHE) {return parseInt(upCdmicBoI,ntcdffaDHE);}" fullword ascii
    $s14 = "function coUiV(yeCLPsBpHnQ,LtohFNWjJZUdC,mzLjIBLr){FxpQ=xwejwsvaiVNZrDNQU(yeCLPsBpHnQ,LtohFNWjJZUdC);MFjXN=FxpQ.toString(mzLjIBL" ascii
    $s15 = "var A = new Array();A[0]=[];A[0][0]='d';A[0][1]='a';A[0][2]='d';A[0][3]='a';A[0][4]='46';A[0][5]='3d';A[0][6]='42';A[0][7]='14';" ascii
    $s16 = "function bQslxDBlkGboauObRZiuIuHjxTuPsYcMBaYFIexOyJpxsRejKIsgpQ(iGrQdaenqCXwz,nuPrzpvEtsATTY){ return GbfNynl[qYCssvsf[coUiV(iGr" ascii
    $s17 = "function vsDzQvEISjLbkIP(heHdlXzOogWYZpLUp,HJRiAEjnSVnYFNtvWVpFYYdVnXjskAIUnz,qbGWbAPwXQLQfsvbFsZQTxYsNZpILYLVXWE){eval(heHdlXzO" ascii
    $s18 = "function frVeddiJyYX(gEjOCPUdoqCFyr) {return isNaN(gEjOCPUdoqCFyr);}" fullword ascii
    $s19 = "function w(djmbVqILGtqDRY,VtGdAOFteArRT,PZojQegbioQ) {djmbVqILGtqDRY[VtGdAOFteArRT]=PZojQegbioQ;}" fullword ascii
    $s20 = "function IzbkypK(TUvZYiRjCoIinifrOPNnJVFkZrJoReVyoLEN) {return !frVeddiJyYX(wHhRURyuGBxHozm(TUvZYiRjCoIinifrOPNnJVFkZrJoReVyoLEN" ascii

  condition:
    uint16(0) == 0x5971 and
    8 of them
}