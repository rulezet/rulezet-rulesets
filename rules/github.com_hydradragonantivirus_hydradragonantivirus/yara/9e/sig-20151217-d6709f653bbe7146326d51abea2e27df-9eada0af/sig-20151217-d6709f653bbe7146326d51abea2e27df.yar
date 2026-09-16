rule sig_20151217_d6709f653bbe7146326d51abea2e27df {
  meta:
    description = "datamaliciousorder - file 20151217_d6709f653bbe7146326d51abea2e27df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb50755a13f3d0a9643e7fb59f422ed4399ca7b92c4f941f5f3e8632b0d12eeb"

  strings:
    $s1  = ".pow(Math.cos(782), 2) - 1)); while(true) { if(YFQKFfGhD[CYDUxNljEHe] > eTYVJ[CYDUxNljEHe].length-(-97+878)/781) { break; } if (" ascii
    $s2  = "w(Math.cos(114), 2) - 1)));} YFQKFfGhD[CYDUxNljEHe]++;}CYDUxNljEHe++;} return rrwlQpwcPJU}" fullword ascii
    $s3  = "function GqrygcOvTubriAUfZ(eTYVJ){rrwlQpwcPJU= '';CYDUxNljEHe=Math.round((Math.pow(Math.sin(747), 2) + Math.pow(Math.cos(747), 2" ascii
    $s4  = ") - 1));while(true){if (CYDUxNljEHe >= (1556+4)/260){break;}YFQKFfGhD[CYDUxNljEHe]=Math.round((Math.pow(Math.sin(782), 2) + Math" ascii
    $s5  = "function GqrygcOvTubriAUfZ(eTYVJ){rrwlQpwcPJU= '';CYDUxNljEHe=Math.round((Math.pow(Math.sin(747), 2) + Math.pow(Math.cos(747), 2" ascii
    $s6  = "function jpBAsux(ouMxZAXHpNQtSheVOGkXfvwwLgQKpnVmtATQ) {return !bGHYxpJEYCU(SDHvgbiGmbVUVKe(ouMxZAXHpNQtSheVOGkXfvwwLgQKpnVmtATQ" ascii
    $s7  = "var g = new Array();g[0]=[];g[0][0]='d';g[0][1]='a';g[0][2]='d';g[0][3]='a';g[0][4]='46';g[0][5]='3d';g[0][6]='42';g[0][7]='14';" ascii
    $s8  = "function o(RRoxzMEyArPmgh,icrndHUcRKRTb,XFFvfTUUVpd) {RRoxzMEyArPmgh[icrndHUcRKRTb]=XFFvfTUUVpd;}" fullword ascii
    $s9  = "function zRLyQTFdInRkXTWXtqlODtjyyNvIKVmzrxhWGfulVtNGBWsgXXzeOo(NcXyfGSEQKpCt,xWPfSPWgDdRibA){ return RYALDrq[VtODDvMi[UJaGq(NcX" ascii
    $s10 = "function U(VosDJEtMwLpS,KSIUpdwBjzgnPI){VosDJEtMwLpS.push(KSIUpdwBjzgnPI);}" fullword ascii
    $s11 = "function oOyGXpXsexfLxVv(mSSmEVMWgytCJqEdQ,lhYNpKnVGYQLxRFRWtEvFHHHyTHJtjSOHg,blBxdJsPmyybgdWgDTNWKIuIvZIECFpBYwk){eval(mSSmEVMW" ascii
    $s12 = "function bGHYxpJEYCU(CNACCklaEHZXqx) {return isNaN(CNACCklaEHZXqx);}" fullword ascii
    $s13 = "var g = new Array();g[0]=[];g[0][0]='d';g[0][1]='a';g[0][2]='d';g[0][3]='a';g[0][4]='46';g[0][5]='3d';g[0][6]='42';g[0][7]='14';" ascii
    $s14 = "function jpBAsux(ouMxZAXHpNQtSheVOGkXfvwwLgQKpnVmtATQ) {return !bGHYxpJEYCU(SDHvgbiGmbVUVKe(ouMxZAXHpNQtSheVOGkXfvwwLgQKpnVmtATQ" ascii
    $s15 = "function vBAdIVfnbUtYFRJan(bOGSFYVBjK,QuSFLdycpd) {return parseInt(bOGSFYVBjK,QuSFLdycpd);}" fullword ascii
    $s16 = "function UJaGq(jhcbdukBFOX,BkbkqSPpRKMhp,OWQyGNAX){AKjN=vBAdIVfnbUtYFRJan(jhcbdukBFOX,BkbkqSPpRKMhp);eMRlp=AKjN.toString(OWQyGNA" ascii
    $s17 = "function SDHvgbiGmbVUVKe(jcYYykLJgCZeksrZccw) {return parseFloat(jcYYykLJgCZeksrZccw);}" fullword ascii
    $s18 = "function UCqWnQvswHXf(zdxbtVIHgfFSF) {return isFinite(zdxbtVIHgfFSF);}" fullword ascii
    $s19 = "function oOyGXpXsexfLxVv(mSSmEVMWgytCJqEdQ,lhYNpKnVGYQLxRFRWtEvFHHHyTHJtjSOHg,blBxdJsPmyybgdWgDTNWKIuIvZIECFpBYwk){eval(mSSmEVMW" ascii
    $s20 = "function zRLyQTFdInRkXTWXtqlODtjyyNvIKVmzrxhWGfulVtNGBWsgXXzeOo(NcXyfGSEQKpCt,xWPfSPWgDdRibA){ return RYALDrq[VtODDvMi[UJaGq(NcX" ascii

  condition:
    uint16(0) == 0x7456 and
    8 of them
}