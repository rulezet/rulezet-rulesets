rule sig_20151216_2083e4b703132fe425fb14033c76adcf {
  meta:
    description = "datamaliciousorder - file 20151216_2083e4b703132fe425fb14033c76adcf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79e27b938d91c1354102d7d26550cfa5f38967b2d4446e4db1480d3f26c1e2c2"

  strings:
    $s1  = "function SRAnIupwNDrGbumNU(GATPC){IsgIjeEoRer= '';SvfztROTcNN=Math.round((Math.pow(Math.sin(53), 2) + Math.pow(Math.cos(53), 2) " ascii
    $s2  = "w(Math.cos(81), 2) - 1)));} aGnLiNiOD[SvfztROTcNN]++;}SvfztROTcNN++;} return IsgIjeEoRer}" fullword ascii
    $s3  = ".pow(Math.cos(818), 2) - 1)); while(true) { if(aGnLiNiOD[SvfztROTcNN] > GATPC[SvfztROTcNN].length-(-434+951)/517) { break; } if " ascii
    $s4  = "function SRAnIupwNDrGbumNU(GATPC){IsgIjeEoRer= '';SvfztROTcNN=Math.round((Math.pow(Math.sin(53), 2) + Math.pow(Math.cos(53), 2) " ascii
    $s5  = "- 1));while(true){if (SvfztROTcNN >= (4618+590)/868){break;}aGnLiNiOD[SvfztROTcNN]=Math.round((Math.pow(Math.sin(818), 2) + Math" ascii
    $s6  = "function FWgIhxK(SAJhUggmWmIuQsSzAGDiTMryTuFTkfBvykbE) {return !rcrDRVECpnj(VcIBPEQnQpmUmoN(SAJhUggmWmIuQsSzAGDiTMryTuFTkfBvykbE" ascii
    $s7  = "p);return OOzWK;}" fullword ascii
    $s8  = "function m(SxCKESvFmpZjfu,uuCxKAUObFVKj,ikWpOwmgOIv) {SxCKESvFmpZjfu[uuCxKAUObFVKj]=ikWpOwmgOIv;}" fullword ascii
    $s9  = "function zaaXipwIFnLGRxudk(wcTJQAfpkg,yFxqJYyLZK) {return parseInt(wcTJQAfpkg,yFxqJYyLZK);}" fullword ascii
    $s10 = "function MLDbrHcjfMuZHQU(hoKFHxpIFrAwWMYEy,MWxSwtoKFKXwqOLfhOMaQzGFBisILVodWT,LtuZJHBfZsJYFRdUcjNMzvjtMgTqYbmJxqL){eval(hoKFHxpI" ascii
    $s11 = "function FWgIhxK(SAJhUggmWmIuQsSzAGDiTMryTuFTkfBvykbE) {return !rcrDRVECpnj(VcIBPEQnQpmUmoN(SAJhUggmWmIuQsSzAGDiTMryTuFTkfBvykbE" ascii
    $s12 = "function dievlVKRjUpGPMMcUNgSHIqxlPJfKFuPfYuzxRoCcHLrfONOmtqdXl(bnTgmgpVzdtxI,XZcKLWRlARHaEg){ return glwSRxT[GyHYpydJ[qqnER(bnT" ascii
    $s13 = "function Q(roBguUxJmzFG,dfALQUhjFQcgKj){roBguUxJmzFG.push(dfALQUhjFQcgKj);}" fullword ascii
    $s14 = "function MLDbrHcjfMuZHQU(hoKFHxpIFrAwWMYEy,MWxSwtoKFKXwqOLfhOMaQzGFBisILVodWT,LtuZJHBfZsJYFRdUcjNMzvjtMgTqYbmJxqL){eval(hoKFHxpI" ascii
    $s15 = "var j = new Array();j[0]=[];j[0][0]='d';j[0][1]='a';j[0][2]='d';j[0][3]='a';j[0][4]='46';j[0][5]='3d';j[0][6]='42';j[0][7]='14';" ascii
    $s16 = "function qqnER(CJawswbASct,ufOJeSZdAfoTx,ziWXuvgp){AsBr=zaaXipwIFnLGRxudk(CJawswbASct,ufOJeSZdAfoTx);OOzWK=AsBr.toString(ziWXuvg" ascii
    $s17 = "function PrRiczrTNjwT(IjrnkmKcltgGi) {return isFinite(IjrnkmKcltgGi);}" fullword ascii
    $s18 = "function VcIBPEQnQpmUmoN(OosyPUXyhCpsQniANns) {return parseFloat(OosyPUXyhCpsQniANns);}" fullword ascii
    $s19 = "function rcrDRVECpnj(RYLePlTySsJBKC) {return isNaN(RYLePlTySsJBKC);}" fullword ascii
    $s20 = "function dievlVKRjUpGPMMcUNgSHIqxlPJfKFuPfYuzxRoCcHLrfONOmtqdXl(bnTgmgpVzdtxI,XZcKLWRlARHaEg){ return glwSRxT[GyHYpydJ[qqnER(bnT" ascii

  condition:
    uint16(0) == 0x7947 and
    8 of them
}