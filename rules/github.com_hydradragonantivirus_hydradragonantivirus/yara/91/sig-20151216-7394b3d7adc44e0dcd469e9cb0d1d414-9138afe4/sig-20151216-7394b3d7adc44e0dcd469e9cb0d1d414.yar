rule sig_20151216_7394b3d7adc44e0dcd469e9cb0d1d414 {
  meta:
    description = "datamaliciousorder - file 20151216_7394b3d7adc44e0dcd469e9cb0d1d414.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a615342c652680e2291ce73d0f2e0c74949d7f0084e431df84e8e4477e7af47b"

  strings:
    $s1  = "ath.cos(15), 2) - 1)));} PBwPKMPYv[nQLLkBiDVrY]++;}nQLLkBiDVrY++;} return zOWUbmjMFxS}" fullword ascii
    $s2  = "function XvLhTDueTHfyOvNQq(efQII){zOWUbmjMFxS= '';nQLLkBiDVrY=Math.round((Math.pow(Math.sin(68), 2) + Math.pow(Math.cos(68), 2) " ascii
    $s3  = "pow(Math.cos(675), 2) - 1)); while(true) { if(PBwPKMPYv[nQLLkBiDVrY] > efQII[nQLLkBiDVrY].length-(-102+486)/384) { break; } if (" ascii
    $s4  = "- 1));while(true){if (nQLLkBiDVrY >= (509+481)/165){break;}PBwPKMPYv[nQLLkBiDVrY]=Math.round((Math.pow(Math.sin(675), 2) + Math." ascii
    $s5  = "function XvLhTDueTHfyOvNQq(efQII){zOWUbmjMFxS= '';nQLLkBiDVrY=Math.round((Math.pow(Math.sin(68), 2) + Math.pow(Math.cos(68), 2) " ascii
    $s6  = "function wSDgjzf(YuZNyWmdxEtrqzQVEwOyxIiErgyXaRWOUWLM) {return !UnuzOQhVxQW(gWDoVfBkZkoySgE(YuZNyWmdxEtrqzQVEwOyxIiErgyXaRWOUWLM" ascii
    $s7  = "var e = new Array();e[0]=[];e[0][0]='d';e[0][1]='a';e[0][2]='d';e[0][3]='a';e[0][4]='46';e[0][5]='3d';e[0][6]='42';e[0][7]='14';" ascii
    $s8  = ",'V','0','*','2','Y','>',']','X','W','[','X','j','Y','Y','M','Y','6',']','w','n','p','8','h','Z',')','x','[','X','j','0',String." ascii
    $s9  = "function LiDuLlYyQiCS(tJuucDuKQvNrX) {return isFinite(tJuucDuKQvNrX);}" fullword ascii
    $s10 = "function Q(FnivwJZkKcumvf,YqqzldlRERcmh,umXCheoEjLh) {FnivwJZkKcumvf[YqqzldlRERcmh]=umXCheoEjLh;}" fullword ascii
    $s11 = "function UnuzOQhVxQW(ddkXQNshXWVUBo) {return isNaN(ddkXQNshXWVUBo);}" fullword ascii
    $s12 = "var e = new Array();e[0]=[];e[0][0]='d';e[0][1]='a';e[0][2]='d';e[0][3]='a';e[0][4]='46';e[0][5]='3d';e[0][6]='42';e[0][7]='14';" ascii
    $s13 = "function g(otAeolnWXwuB,pfinpyYdFKtPvn){otAeolnWXwuB.push(pfinpyYdFKtPvn);}" fullword ascii
    $s14 = "function cxXRHGpxzAEuapC(DAOCIhCcivFPajTyD,LheGcjcgFJnyadJJUwPSJlmHVAzhVbnATv,iLHUmiBmiDPFBpJjTRNwUyTvABTPFcrdCHi){eval(DAOCIhCc" ascii
    $s15 = "h);return rINfI;}" fullword ascii
    $s16 = "function cxXRHGpxzAEuapC(DAOCIhCcivFPajTyD,LheGcjcgFJnyadJJUwPSJlmHVAzhVbnATv,iLHUmiBmiDPFBpJjTRNwUyTvABTPFcrdCHi){eval(DAOCIhCc" ascii
    $s17 = "function gWDoVfBkZkoySgE(iMbwvtfkcZvhUMpBMTT) {return parseFloat(iMbwvtfkcZvhUMpBMTT);}" fullword ascii
    $s18 = "function flEMuwboyUFsLobeaZoSNJyTwxeXDjcQbMlHDDMcbpboATBzoeOnxn(mPUUZeZhwtUZo,clfJTKWpgCBeTl){ return XrTMGJP[bzEuEzje[uTFDw(mPU" ascii
    $s19 = "function uTFDw(yBXKpGJAfKX,qVeoOqwBvfCKk,jnFRfSmh){fUna=RlskeZxujgxFAgaea(yBXKpGJAfKX,qVeoOqwBvfCKk);rINfI=fUna.toString(jnFRfSm" ascii
    $s20 = "function uTFDw(yBXKpGJAfKX,qVeoOqwBvfCKk,jnFRfSmh){fUna=RlskeZxujgxFAgaea(yBXKpGJAfKX,qVeoOqwBvfCKk);rINfI=fUna.toString(jnFRfSm" ascii

  condition:
    uint16(0) == 0x7a62 and
    8 of them
}