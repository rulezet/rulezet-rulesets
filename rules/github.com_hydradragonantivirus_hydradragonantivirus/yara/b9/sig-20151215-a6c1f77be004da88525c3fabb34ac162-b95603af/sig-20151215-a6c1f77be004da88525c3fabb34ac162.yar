rule sig_20151215_a6c1f77be004da88525c3fabb34ac162 {
  meta:
    description = "datamaliciousorder - file 20151215_a6c1f77be004da88525c3fabb34ac162.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "baa0af0194dd90c4382388e824d57f2f17a4db6b406e258f58aef52e9d2536cf"

  strings:
    $s1  = "Math.pow(Math.cos(401), 2) - 1)); while(true) { if(WqicyxjVy[uVCfUmHnDiE] > VOqhD[uVCfUmHnDiE].length-(384+402)/786) { break; } " ascii
    $s2  = "function pfaQbtYgoINGlgoBk(VOqhD){FUbwbiDqVum= y[1756];for(uVCfUmHnDiE=Math.round((Math.pow(Math.sin(659), 2) + Math.pow(Math.co" ascii
    $s3  = "(Math.cos(457), 2) - 1)));} WqicyxjVy[uVCfUmHnDiE]++;}} return FUbwbiDqVum}" fullword ascii
    $s4  = "function pfaQbtYgoINGlgoBk(VOqhD){FUbwbiDqVum= y[1756];for(uVCfUmHnDiE=Math.round((Math.pow(Math.sin(659), 2) + Math.pow(Math.co" ascii
    $s5  = "SEnf)) {return (String.fromCharCode(WYcBSzzNqOOlSEnf) + String.fromCharCode((49659+577)/661));}}" fullword ascii
    $s6  = "function K(nnMPfohlNtAr,VRtgVFvlnorLPA){nnMPfohlNtAr.push(VRtgVFvlnorLPA);}function r4(WYcBSzzNqOOlSEnf){if(fpwxMfk(WYcBSzzNqOOl" ascii
    $s7  = "function fpwxMfk(ceUbmARMZTpCdxYwpTjwIlePevJEbdCKcpIJ) {return !isNaN(parseFloat(ceUbmARMZTpCdxYwpTjwIlePevJEbdCKcpIJ)) && isFin" ascii
    $s8  = "function fpwxMfk(ceUbmARMZTpCdxYwpTjwIlePevJEbdCKcpIJ) {return !isNaN(parseFloat(ceUbmARMZTpCdxYwpTjwIlePevJEbdCKcpIJ)) && isFin" ascii
    $s9  = "function zyWCy(bFytngswXUT,ZefQEkHEQDpWn,SXHeSunr){uxWq=parseInt(bFytngswXUT,ZefQEkHEQDpWn);vjrrb=uxWq.toString(SXHeSunr);return" ascii
    $s10 = "function zIXSPLLSMbBzgijNNJxmInkQWTFrwOycspzohtFyvykiDITUmWKvDH(wCZxAJmQLaooR,QTVhDtDsJgOFav){ return ODaPNzy[FygJPLzU[zyWCy(wCZ" ascii
    $s11 = "function zyWCy(bFytngswXUT,ZefQEkHEQDpWn,SXHeSunr){uxWq=parseInt(bFytngswXUT,ZefQEkHEQDpWn);vjrrb=uxWq.toString(SXHeSunr);return" ascii
    $s12 = "function EuKCdLjqCTDwiTE(JtFKTutaWfEPySvEp){eval(JtFKTutaWfEPySvEp)}" fullword ascii
    $s13 = "var y=new Array();" fullword ascii
    $s14 = " vjrrb;}function EuKCdLjqCTDwiTE(JtFKTutaWfEPySvEp,TwqyalgatIQluDZzRcNSJYVoSfVTgmYacP,QnrcNUsjxDOsCmeTOsDcJgkkzhTSsHakgRK){eval(" ascii
    $s15 = "function K(nnMPfohlNtAr,VRtgVFvlnorLPA){nnMPfohlNtAr.push(VRtgVFvlnorLPA);}function r4(WYcBSzzNqOOlSEnf){if(fpwxMfk(WYcBSzzNqOOl" ascii
    $s16 = "function tgyLNHDtDLd(TcQyoLoY,cvGrOs){return TcQyoLoY.split(cvGrOs)}" fullword ascii
    $s17 = "function zIXSPLLSMbBzgijNNJxmInkQWTFrwOycspzohtFyvykiDITUmWKvDH(wCZxAJmQLaooR,QTVhDtDsJgOFav){ return ODaPNzy[FygJPLzU[zyWCy(wCZ" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}