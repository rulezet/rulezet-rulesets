rule sig_20151216_32bf64597a52cf5aafa1ab535814ca5e {
  meta:
    description = "datamaliciousorder - file 20151216_32bf64597a52cf5aafa1ab535814ca5e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00eeb0c3144af0b0a8476af3dc47560166ff0524d90fba3ec18aeb97a56a8535"

  strings:
    $s1  = ") - 1));while(true){if (rcvJnxjLqqw >= (5601+81)/947){break;}FdoodFgRo[rcvJnxjLqqw]=Math.round((Math.pow(Math.sin(377), 2) + Mat" ascii
    $s2  = "ow(Math.cos(300), 2) - 1)));} FdoodFgRo[rcvJnxjLqqw]++;}rcvJnxjLqqw++;} return LmnNFPcHfpc}" fullword ascii
    $s3  = "function isKTOEyciTuiTWmQu(CAHVl){LmnNFPcHfpc= '';rcvJnxjLqqw=Math.round((Math.pow(Math.sin(739), 2) + Math.pow(Math.cos(739), 2" ascii
    $s4  = "h.pow(Math.cos(377), 2) - 1)); while(true) { if(FdoodFgRo[rcvJnxjLqqw] > CAHVl[rcvJnxjLqqw].length-(-373+795)/422) { break; } if" ascii
    $s5  = "function isKTOEyciTuiTWmQu(CAHVl){LmnNFPcHfpc= '';rcvJnxjLqqw=Math.round((Math.pow(Math.sin(739), 2) + Math.pow(Math.cos(739), 2" ascii
    $s6  = "function e(loOYrRiQYvVQNq,GjlcNjXnHOAnm,pEHjJYNesIs) {loOYrRiQYvVQNq[GjlcNjXnHOAnm]=pEHjJYNesIs;}" fullword ascii
    $s7  = "function lCJYBEciWlJMAPUxiwYxnfnUzkUKZrjkurWHLXVqarucJSmSFcuyFi(SDQuuNALJVhnT,QlpBgZBsqsWBlx){ return GbbZahY[SNvmAaic[BhJWg(SDQ" ascii
    $s8  = "S);return MCiYI;}" fullword ascii
    $s9  = "function lCJYBEciWlJMAPUxiwYxnfnUzkUKZrjkurWHLXVqarucJSmSFcuyFi(SDQuuNALJVhnT,QlpBgZBsqsWBlx){ return GbbZahY[SNvmAaic[BhJWg(SDQ" ascii
    $s10 = "function PXbOSZzfeqwF(ALleMjPfzChGl) {return isFinite(ALleMjPfzChGl);}" fullword ascii
    $s11 = "function DPorrzTJhDUjTfnil(WSkvXMINKt,jPWnRiXbWE) {return parseInt(WSkvXMINKt,jPWnRiXbWE);}" fullword ascii
    $s12 = "function BhJWg(PBmIhNHndOw,DQYcMqIvYSdXK,YrjHQEOS){NlTs=DPorrzTJhDUjTfnil(PBmIhNHndOw,DQYcMqIvYSdXK);MCiYI=NlTs.toString(YrjHQEO" ascii
    $s13 = "var r = new Array();r[0]=[];r[0][0]='d';r[0][1]='a';r[0][2]='d';r[0][3]='a';r[0][4]='46';r[0][5]='3d';r[0][6]='42';r[0][7]='14';" ascii
    $s14 = "function HhytkCDNpnS(vLVEhypDmBJTOw) {return isNaN(vLVEhypDmBJTOw);}" fullword ascii
    $s15 = "function DXqrzAWoSHVovPp(FVHamZOSzyhmkDSbWox) {return parseFloat(FVHamZOSzyhmkDSbWox);}" fullword ascii
    $s16 = "function U(pUotqQNIFNJt,urbsqGTsvLMdAl){pUotqQNIFNJt.push(urbsqGTsvLMdAl);}" fullword ascii
    $s17 = "function BhJWg(PBmIhNHndOw,DQYcMqIvYSdXK,YrjHQEOS){NlTs=DPorrzTJhDUjTfnil(PBmIhNHndOw,DQYcMqIvYSdXK);MCiYI=NlTs.toString(YrjHQEO" ascii
    $s18 = "function UggjlRo(DvRCaXNxzEEWYtwIDEiUebJxCdqHDGYbkMVn) {return !HhytkCDNpnS(DXqrzAWoSHVovPp(DvRCaXNxzEEWYtwIDEiUebJxCdqHDGYbkMVn" ascii
    $s19 = "function AgjLTCQsvMXbXRX(bUHTIbEnRBzeNTiHD,kMiqVvBTZacaDATOKcSfrrKxXuvzJxQGye,LPHODmbeNfsNjxamYwkVISZPhfaLYgFwjDH){eval(bUHTIbEn" ascii
    $s20 = "function UggjlRo(DvRCaXNxzEEWYtwIDEiUebJxCdqHDGYbkMVn) {return !HhytkCDNpnS(DXqrzAWoSHVovPp(DvRCaXNxzEEWYtwIDEiUebJxCdqHDGYbkMVn" ascii

  condition:
    uint16(0) == 0x4e53 and
    8 of them
}