rule sig_20151217_a7da67aa4556e9d5c600965679e29931 {
  meta:
    description = "datamaliciousorder - file 20151217_a7da67aa4556e9d5c600965679e29931.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd2cb928782452a16c70075e2372bc88aa1a1d9aed20a922fa67b4d9da22de1c"

  strings:
    $s1  = ") - 1));while(true){if (yLwrTbWHReV >= (1155+663)/303){break;}mCSDwLfsB[yLwrTbWHReV]=Math.round((Math.pow(Math.sin(294), 2) + Ma" ascii
    $s2  = "ow(Math.cos(857), 2) - 1)));} mCSDwLfsB[yLwrTbWHReV]++;}yLwrTbWHReV++;} return qazfcQMaMzW}" fullword ascii
    $s3  = "th.pow(Math.cos(294), 2) - 1)); while(true) { if(mCSDwLfsB[yLwrTbWHReV] > oWDep[yLwrTbWHReV].length-(-301+893)/592) { break; } i" ascii
    $s4  = "function hVZheIsGlLzdopQIN(oWDep){qazfcQMaMzW= '';yLwrTbWHReV=Math.round((Math.pow(Math.sin(921), 2) + Math.pow(Math.cos(921), 2" ascii
    $s5  = "function hVZheIsGlLzdopQIN(oWDep){qazfcQMaMzW= '';yLwrTbWHReV=Math.round((Math.pow(Math.sin(921), 2) + Math.pow(Math.cos(921), 2" ascii
    $s6  = "function bkJibii(JjnaZkjJqyQFvjuqQSSBjMizpFQRDnSRvbSj) {return !LzLLVnLlpTL(sYvBRlVvIkwYRmm(JjnaZkjJqyQFvjuqQSSBjMizpFQRDnSRvbSj" ascii
    $s7  = "var d = new Array();d[0]=[];d[0][0]='d';d[0][1]='a';d[0][2]='d';d[0][3]='a';d[0][4]='46';d[0][5]='3d';d[0][6]='42';d[0][7]='14';" ascii
    $s8  = "function vLiZf(SxDcOtgUCqA,ovMcGxGlkePdF,wuxVHPWJ){GHXz=PlZRqlokNMRqbZZsq(SxDcOtgUCqA,ovMcGxGlkePdF);AOaTh=GHXz.toString(wuxVHPW" ascii
    $s9  = "function LSxnkVGkhkXXUat(MKMjPDIGnnXKTWfPZ,yCPQCirLJyZdkrmSAvwgYCmatxJXkizIVF,duinKNWbqVXAupyDybvbQpfvegyRVgPwnqr){eval(MKMjPDIG" ascii
    $s10 = "function O(NAIvUMdkobrAjN,CXnSAjYUcXkfG,WHjNNcPBWlX) {NAIvUMdkobrAjN[CXnSAjYUcXkfG]=WHjNNcPBWlX;}" fullword ascii
    $s11 = "function ApeuMehuwlcPUzrfLujiIFmgKKtijGivNoxqIUjiCSZghexiaXPNdm(xYqKSatrKktBF,QvVqHdNVFNNGtO){ return FWivKlk[sBdnTxdk[vLiZf(xYq" ascii
    $s12 = "function i(EUbEoBjkPZkU,QUxjAhURvbbktk){EUbEoBjkPZkU.push(QUxjAhURvbbktk);}" fullword ascii
    $s13 = "function vLiZf(SxDcOtgUCqA,ovMcGxGlkePdF,wuxVHPWJ){GHXz=PlZRqlokNMRqbZZsq(SxDcOtgUCqA,ovMcGxGlkePdF);AOaTh=GHXz.toString(wuxVHPW" ascii
    $s14 = "function sYvBRlVvIkwYRmm(mrcrVLNcQlPlCPQKSbL) {return parseFloat(mrcrVLNcQlPlCPQKSbL);}" fullword ascii
    $s15 = "var d = new Array();d[0]=[];d[0][0]='d';d[0][1]='a';d[0][2]='d';d[0][3]='a';d[0][4]='46';d[0][5]='3d';d[0][6]='42';d[0][7]='14';" ascii
    $s16 = "function LzLLVnLlpTL(oWnYdaxVBehQAP) {return isNaN(oWnYdaxVBehQAP);}" fullword ascii
    $s17 = "function PlZRqlokNMRqbZZsq(diaNcoYNWy,ARCiCSNilz) {return parseInt(diaNcoYNWy,ARCiCSNilz);}" fullword ascii
    $s18 = "function LSxnkVGkhkXXUat(MKMjPDIGnnXKTWfPZ,yCPQCirLJyZdkrmSAvwgYCmatxJXkizIVF,duinKNWbqVXAupyDybvbQpfvegyRVgPwnqr){eval(MKMjPDIG" ascii
    $s19 = "function grFzEqaFnJlz(JyQYrhDNInefs) {return isFinite(JyQYrhDNInefs);}" fullword ascii
    $s20 = "J);return AOaTh;}" fullword ascii

  condition:
    uint16(0) == 0x4273 and
    8 of them
}