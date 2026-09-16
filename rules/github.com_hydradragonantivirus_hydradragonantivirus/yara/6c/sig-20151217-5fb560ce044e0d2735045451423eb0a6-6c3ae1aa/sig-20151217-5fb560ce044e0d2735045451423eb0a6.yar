rule sig_20151217_5fb560ce044e0d2735045451423eb0a6 {
  meta:
    description = "datamaliciousorder - file 20151217_5fb560ce044e0d2735045451423eb0a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9299359eea86ce2d12c2c7a6181097f7ce7f1ef876749c56e8fa2ea370641598"

  strings:
    $s1  = ") - 1));while(true){if (sDwBGfQXElY >= (908+598)/251){break;}czOPcaGYW[sDwBGfQXElY]=Math.round((Math.pow(Math.sin(810), 2) + Mat" ascii
    $s2  = "function KyzwvAobWVXwvHxUo(BZvMq){yRYUjFEgxzV= '';sDwBGfQXElY=Math.round((Math.pow(Math.sin(856), 2) + Math.pow(Math.cos(856), 2" ascii
    $s3  = "ow(Math.cos(323), 2) - 1)));} czOPcaGYW[sDwBGfQXElY]++;}sDwBGfQXElY++;} return yRYUjFEgxzV}" fullword ascii
    $s4  = "h.pow(Math.cos(810), 2) - 1)); while(true) { if(czOPcaGYW[sDwBGfQXElY] > BZvMq[sDwBGfQXElY].length-(-709+723)/14) { break; } if " ascii
    $s5  = "function KyzwvAobWVXwvHxUo(BZvMq){yRYUjFEgxzV= '';sDwBGfQXElY=Math.round((Math.pow(Math.sin(856), 2) + Math.pow(Math.cos(856), 2" ascii
    $s6  = "function qLMNmmN(YhiZowARAYAOttgARtJXYTYdwThyLyDbHZnZ) {return !zLasUZZKBlC(hlDKYwkiIfpWOYv(YhiZowARAYAOttgARtJXYTYdwThyLyDbHZnZ" ascii
    $s7  = "function s(WQeuVqCtEqCo,ZwvjrqIQEBMKey){WQeuVqCtEqCo.push(ZwvjrqIQEBMKey);}" fullword ascii
    $s8  = "var S = new Array();S[0]=[];S[0][0]='d';S[0][1]='a';S[0][2]='d';S[0][3]='a';S[0][4]='46';S[0][5]='3d';S[0][6]='42';S[0][7]='14';" ascii
    $s9  = "function CsaKe(urmaLnpLjSC,dtAKqHUKukQMs,yADHdAIU){PReT=BkxbTPBJLcOAXqrws(urmaLnpLjSC,dtAKqHUKukQMs);TQtdk=PReT.toString(yADHdAI" ascii
    $s10 = "function xlLTTwTRMmbkKbi(vgIlwHAGbLomLfFSe,BvhPsqkqrHIkAhkVufvsvBDcpwKdCuyFdE,GuHulZHBLlRDQgXRRStBzPEYTTUSGSIkLmp){eval(vgIlwHAG" ascii
    $s11 = "function ibyPuNLgHaDGPirqpFwGecJoDjfjaBuJTUFzqVPNDyCJPzpZpjnXGN(cHRmRbxciRpmd,hlMYozHAJgCbNi){ return xbEkLnh[tWdrUEbn[CsaKe(cHR" ascii
    $s12 = "var S = new Array();S[0]=[];S[0][0]='d';S[0][1]='a';S[0][2]='d';S[0][3]='a';S[0][4]='46';S[0][5]='3d';S[0][6]='42';S[0][7]='14';" ascii
    $s13 = "function qLMNmmN(YhiZowARAYAOttgARtJXYTYdwThyLyDbHZnZ) {return !zLasUZZKBlC(hlDKYwkiIfpWOYv(YhiZowARAYAOttgARtJXYTYdwThyLyDbHZnZ" ascii
    $s14 = "function xlLTTwTRMmbkKbi(vgIlwHAGbLomLfFSe,BvhPsqkqrHIkAhkVufvsvBDcpwKdCuyFdE,GuHulZHBLlRDQgXRRStBzPEYTTUSGSIkLmp){eval(vgIlwHAG" ascii
    $s15 = "function n(NjadKxgJktJRQM,cHkETWNJTcxRv,bVVUJhudXbE) {NjadKxgJktJRQM[cHkETWNJTcxRv]=bVVUJhudXbE;}" fullword ascii
    $s16 = "function BkxbTPBJLcOAXqrws(GzuAVZWdbW,jyMRvmhQPB) {return parseInt(GzuAVZWdbW,jyMRvmhQPB);}" fullword ascii
    $s17 = "function zLasUZZKBlC(WIWYpTIWDJbTIy) {return isNaN(WIWYpTIWDJbTIy);}" fullword ascii
    $s18 = "U);return TQtdk;}" fullword ascii
    $s19 = "function hlDKYwkiIfpWOYv(xGzaaLauxEslquhTpIM) {return parseFloat(xGzaaLauxEslquhTpIM);}" fullword ascii
    $s20 = "function CsaKe(urmaLnpLjSC,dtAKqHUKukQMs,yADHdAIU){PReT=BkxbTPBJLcOAXqrws(urmaLnpLjSC,dtAKqHUKukQMs);TQtdk=PReT.toString(yADHdAI" ascii

  condition:
    uint16(0) == 0x5774 and
    8 of them
}