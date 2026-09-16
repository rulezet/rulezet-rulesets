rule sig_20151217_2a091a8485b2567cd536eda317abfc09 {
  meta:
    description = "datamaliciousorder - file 20151217_2a091a8485b2567cd536eda317abfc09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d1e62dc0533e6092a95bc430b1fdc9a7018bd55d0b5302c71c3c80b6713ba41"

  strings:
    $s1  = "function SqsDURhAPvEsMllkR(abVAO){TPGALBEhUVv= '';SKIeQwomzAH=Math.round((Math.pow(Math.sin(197), 2) + Math.pow(Math.cos(197), 2" ascii
    $s2  = "pow(Math.cos(786), 2) - 1)));} wOakSEbga[SKIeQwomzAH]++;}SKIeQwomzAH++;} return TPGALBEhUVv}" fullword ascii
    $s3  = "th.pow(Math.cos(939), 2) - 1)); while(true) { if(wOakSEbga[SKIeQwomzAH] > abVAO[SKIeQwomzAH].length-(-195+735)/540) { break; } i" ascii
    $s4  = ") - 1));while(true){if (SKIeQwomzAH >= (3936+222)/693){break;}wOakSEbga[SKIeQwomzAH]=Math.round((Math.pow(Math.sin(939), 2) + Ma" ascii
    $s5  = "kQzmGyifWiPVPzaFoMWBeMFSvAckKkpJCMd([abVAO[SKIeQwomzAH][wOakSEbga[SKIeQwomzAH]]], Math.round((Math.pow(Math.sin(786), 2) + Math." ascii
    $s6  = "function eAInjlNMYKRWyevXvNbkQzmGyifWiPVPzaFoMWBeMFSvAckKkpJCMd(dVUkkObzRdZrP,fhfzmDNsWFRkrE){ return CUvAGbE[EeUgiGET[UpOVd(dVU" ascii
    $s7  = "function vvaTAaa(cGVUvZIRCwCtAbBLVrCnHMLudzstChrGmBLg) {return !nBdxRrtmwGA(OzVfsYmLlChHZHv(cGVUvZIRCwCtAbBLVrCnHMLudzstChrGmBLg" ascii
    $s8  = "function eAInjlNMYKRWyevXvNbkQzmGyifWiPVPzaFoMWBeMFSvAckKkpJCMd(dVUkkObzRdZrP,fhfzmDNsWFRkrE){ return CUvAGbE[EeUgiGET[UpOVd(dVU" ascii
    $s9  = "function SqsDURhAPvEsMllkR(abVAO){TPGALBEhUVv= '';SKIeQwomzAH=Math.round((Math.pow(Math.sin(197), 2) + Math.pow(Math.cos(197), 2" ascii
    $s10 = "function vvaTAaa(cGVUvZIRCwCtAbBLVrCnHMLudzstChrGmBLg) {return !nBdxRrtmwGA(OzVfsYmLlChHZHv(cGVUvZIRCwCtAbBLVrCnHMLudzstChrGmBLg" ascii
    $s11 = "var d = new Array();d[0]=[];d[0][0]='d';d[0][1]='a';d[0][2]='d';d[0][3]='a';d[0][4]='46';d[0][5]='3d';d[0][6]='42';d[0][7]='14';" ascii
    $s12 = "function nBdxRrtmwGA(JHhSnHIgCKHiHx) {return isNaN(JHhSnHIgCKHiHx);}" fullword ascii
    $s13 = "function IsoOTAxWypNPVIL(QkHSJwexsUuVbKdzr,FhHMkWejtizfaaZUiOCSvyJuHjrGuFGkFo,vhzeDmQRRQiEeLuMqGlhVRzHmOPBekdlFCJ){eval(QkHSJwex" ascii
    $s14 = "var d = new Array();d[0]=[];d[0][0]='d';d[0][1]='a';d[0][2]='d';d[0][3]='a';d[0][4]='46';d[0][5]='3d';d[0][6]='42';d[0][7]='14';" ascii
    $s15 = "function u(yHUVGLNIFxoYeW,mjHfVfLamQOxg,kGeuStcGZjc) {yHUVGLNIFxoYeW[mjHfVfLamQOxg]=kGeuStcGZjc;}" fullword ascii
    $s16 = "function UpOVd(zGBUeFEbZCY,bXlxfghiqutYH,AviUNhpf){abiR=dTBrsNKCstIiBGGBx(zGBUeFEbZCY,bXlxfghiqutYH);altCY=abiR.toString(AviUNhp" ascii
    $s17 = "function IsoOTAxWypNPVIL(QkHSJwexsUuVbKdzr,FhHMkWejtizfaaZUiOCSvyJuHjrGuFGkFo,vhzeDmQRRQiEeLuMqGlhVRzHmOPBekdlFCJ){eval(QkHSJwex" ascii
    $s18 = "function ZhtYfXIPhoPa(yNFBgZGkwCndK) {return isFinite(yNFBgZGkwCndK);}" fullword ascii
    $s19 = "function O(gGWYZwPsNHjk,hwWnDwnDbAOvYC){gGWYZwPsNHjk.push(hwWnDwnDbAOvYC);}" fullword ascii
    $s20 = "function OzVfsYmLlChHZHv(MeqGWVQOUEguDcDqryt) {return parseFloat(MeqGWVQOUEguDcDqryt);}" fullword ascii

  condition:
    uint16(0) == 0x6545 and
    8 of them
}