rule sig_20160527_17dcb263f3a78cf8c9ae131926c65136 {
  meta:
    description = "datamaliciousorder - file 20160527_17dcb263f3a78cf8c9ae131926c65136.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b3e7978350f7ac2c94b9def07a4a1c0bdbd8b45d315c343f0e0e5e9ae994ec3"

  strings:
    $s1  = "function WLenugKlQsF() {return WScript;}function JVIotGrt(){return QbzNapVRICQT.ExpandEnvironmentStrings(wRObwWaxMl())}" fullword ascii
    $s2  = "function WOQRtYMGhTYPS(nSMEYwZo,nZgaWoqWkuWhBwIK){return nSMEYwZo.charAt(nZgaWoqWkuWhBwIK);}" fullword ascii
    $s3  = "var DQNUM = meDyvGxjZRf.createtextfile(QbzNapVRICQT.ExpandEnvironmentStrings(jLxTlUk[2]+jLxTlUk[3])+String.fromCharCode(92)+jLxT" ascii
    $s4  = "function YwPGrZn(ZGBjTc,fgVXedterWLdiecxqi){return String.fromCharCode(ZGBjTc,fgVXedterWLdiecxqi);}" fullword ascii
    $s5  = "var QbzNapVRICQT=function(){return WLenugKlQsF().CreateObject(jLxTlUk[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s6  = "uNVGPvrbntyunyFbJ += YwPGrZn(YGudkkNbqnOUFZDNKglm, IiAiYrxjnBAOdnlmA);else sllxduNVGPvrbntyunyFbJ += pBzHQkS(YGudkkNbqnOUFZDNKgl" ascii
    $s7  = "function jl(vjVfNyUgwHdRc){return String.fromCharCode(vjVfNyUgwHdRc);}" fullword ascii
    $s8  = "function pBzHQkS(drBnuip,IGpRwxvhqooJxZHO,jpoyBHjnmGbIpWrkBwS){return String.fromCharCode(drBnuip,IGpRwxvhqooJxZHO,jpoyBHjnmGbIp" ascii
    $s9  = "function uBpjLWo(GowhlHTLCEMcw) {var AiKSvUidZsHxnoKwyk = igihgUIgseQsjCKCMyJn.join(jLxTlUk[6]);var YGudkkNbqnOUFZDNKglm, IiAiYr" ascii
    $s10 = "m, IiAiYrxjnBAOdnlmA, ixPWkXuskS);} while (ACdQLmHyTJxREUytV < GowhlHTLCEMcw.length);return sllxduNVGPvrbntyunyFbJ;}" fullword ascii
    $s11 = "function pBzHQkS(drBnuip,IGpRwxvhqooJxZHO,jpoyBHjnmGbIpWrkBwS){return String.fromCharCode(drBnuip,IGpRwxvhqooJxZHO,jpoyBHjnmGbIp" ascii
    $s12 = "function rQFOUasjsZ(){return dfzouTd(jLxTlUk[12],[0,3,6],jLxTlUk[13]);}" fullword ascii
    $s13 = "if (nRKgCdxdRBIilZIsnURl == 64) sllxduNVGPvrbntyunyFbJ += jl(YGudkkNbqnOUFZDNKglm);else if (gruEVMrbCyXOEQKftsOrUxq == 64) sllxd" ascii
    $s14 = "function dfzouTd(PdCUeo,HzIiuHlmUf,lsSBtalyyIo){NMtzPqcOAw=PdCUeo.split(lsSBtalyyIo);UtTgJlWRyxiyGy = jLxTlUk[14];for(GxrzhXpw=0" ascii
    $s15 = "function LjwxAZamR(igwFQn,sFlTcRFczb) {var BVHpSPXZHc=[jLxTlUk[15]];igwFQn[BVHpSPXZHc[0]](sFlTcRFczb,0x1,0x0)}" fullword ascii
    $s16 = "function wRObwWaxMl(){return dfzouTd(jLxTlUk[8],[1,5,7],jLxTlUk[9]);}" fullword ascii
    $s17 = "function uBpjLWo(GowhlHTLCEMcw) {var AiKSvUidZsHxnoKwyk = igihgUIgseQsjCKCMyJn.join(jLxTlUk[6]);var YGudkkNbqnOUFZDNKglm, IiAiYr" ascii
    $s18 = "var meDyvGxjZRf=function(){return new ActiveXObject(jLxTlUk[0]);}();" fullword ascii
    $s19 = "function dfzouTd(PdCUeo,HzIiuHlmUf,lsSBtalyyIo){NMtzPqcOAw=PdCUeo.split(lsSBtalyyIo);UtTgJlWRyxiyGy = jLxTlUk[14];for(GxrzhXpw=0" ascii
    $s20 = "function wFApfHnVVYDeik(oIaVDhlAHUOqUFvZPkKOuK,RCHymesflFam){return oIaVDhlAHUOqUFvZPkKOuK.indexOf(RCHymesflFam);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}