rule sig_20151217_ed8050fdcbb101a917d96a046b5a4eaf {
  meta:
    description = "datamaliciousorder - file 20151217_ed8050fdcbb101a917d96a046b5a4eaf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "936df243edcc373bdcb4d951af3c15b10d393c96261b84fd89db8a6720bc0808"

  strings:
    $s1  = "function QKOhDdyfuqoeAoDwh(DTWXq){rKIAPICnAfL= '';FePnlpOYvpA=Math.round((Math.pow(Math.sin(978), 2) + Math.pow(Math.cos(978), 2" ascii
    $s2  = ") - 1));while(true){if (FePnlpOYvpA >= (118+374)/82){break;}VTKnvUugy[FePnlpOYvpA]=Math.round((Math.pow(Math.sin(145), 2) + Math" ascii
    $s3  = "ow(Math.cos(226), 2) - 1)));} VTKnvUugy[FePnlpOYvpA]++;}FePnlpOYvpA++;} return rKIAPICnAfL}" fullword ascii
    $s4  = ".pow(Math.cos(145), 2) - 1)); while(true) { if(VTKnvUugy[FePnlpOYvpA] > DTWXq[FePnlpOYvpA].length-(-172+977)/805) { break; } if " ascii
    $s5  = "function RrvOwaS(SzrkDNYMOQdSSLSPjsZFbAnuozXRyOFTPLNK) {return !BIovAyqQbDY(uNrqydsRYViAAZR(SzrkDNYMOQdSSLSPjsZFbAnuozXRyOFTPLNK" ascii
    $s6  = "function QKOhDdyfuqoeAoDwh(DTWXq){rKIAPICnAfL= '';FePnlpOYvpA=Math.round((Math.pow(Math.sin(978), 2) + Math.pow(Math.cos(978), 2" ascii
    $s7  = "function RrvOwaS(SzrkDNYMOQdSSLSPjsZFbAnuozXRyOFTPLNK) {return !BIovAyqQbDY(uNrqydsRYViAAZR(SzrkDNYMOQdSSLSPjsZFbAnuozXRyOFTPLNK" ascii
    $s8  = "var F = new Array();F[0]=[];F[0][0]='d';F[0][1]='a';F[0][2]='d';F[0][3]='a';F[0][4]='46';F[0][5]='3d';F[0][6]='42';F[0][7]='14';" ascii
    $s9  = "function EXmqauYLFCrI(uBEeZDbXAjCOJ) {return isFinite(uBEeZDbXAjCOJ);}" fullword ascii
    $s10 = "function Uiouu(fRqnimVQjzx,VgwjOZxGtFIGh,MAHnYTlJ){jxdr=RQJKFeroTQAfRqFoX(fRqnimVQjzx,VgwjOZxGtFIGh);DRmJw=jxdr.toString(MAHnYTl" ascii
    $s11 = "function TpLlrtZJOpPdrYfVzdhPZIudiaUjpWEFIamAAjJuPJawJIxFZzgOgE(bfJJHNueVIrJz,IFIluTGfIqMaRf){ return ZSYcMuV[GKSQbnte[Uiouu(bfJ" ascii
    $s12 = "function BIovAyqQbDY(lsxriYlDduFMgY) {return isNaN(lsxriYlDduFMgY);}" fullword ascii
    $s13 = "function Uiouu(fRqnimVQjzx,VgwjOZxGtFIGh,MAHnYTlJ){jxdr=RQJKFeroTQAfRqFoX(fRqnimVQjzx,VgwjOZxGtFIGh);DRmJw=jxdr.toString(MAHnYTl" ascii
    $s14 = "var F = new Array();F[0]=[];F[0][0]='d';F[0][1]='a';F[0][2]='d';F[0][3]='a';F[0][4]='46';F[0][5]='3d';F[0][6]='42';F[0][7]='14';" ascii
    $s15 = "J);return DRmJw;}" fullword ascii
    $s16 = "function M(zJRQEoJfllHx,ExqYgSGOApMXvJ){zJRQEoJfllHx.push(ExqYgSGOApMXvJ);}" fullword ascii
    $s17 = "function XtBEtKGqjcnPsTa(COPdkcgfYajAInOZW,OPSAZfXftqREOBXNXhqhHxUeUlnIesYaHP,jIPrZgBVNvSmGnGLhDzdhvOGhteVrlskbws){eval(COPdkcgf" ascii
    $s18 = "function XtBEtKGqjcnPsTa(COPdkcgfYajAInOZW,OPSAZfXftqREOBXNXhqhHxUeUlnIesYaHP,jIPrZgBVNvSmGnGLhDzdhvOGhteVrlskbws){eval(COPdkcgf" ascii
    $s19 = "function s(cRXVHdbLrmriVw,dRJxEoiqSbYyM,GoMmkNIzvOj) {cRXVHdbLrmriVw[dRJxEoiqSbYyM]=GoMmkNIzvOj;}" fullword ascii
    $s20 = "function TpLlrtZJOpPdrYfVzdhPZIudiaUjpWEFIamAAjJuPJawJIxFZzgOgE(bfJJHNueVIrJz,IFIluTGfIqMaRf){ return ZSYcMuV[GKSQbnte[Uiouu(bfJ" ascii

  condition:
    uint16(0) == 0x4b47 and
    8 of them
}