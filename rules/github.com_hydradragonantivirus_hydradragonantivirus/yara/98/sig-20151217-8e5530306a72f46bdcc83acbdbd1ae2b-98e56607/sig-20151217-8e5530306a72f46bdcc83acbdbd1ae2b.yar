rule sig_20151217_8e5530306a72f46bdcc83acbdbd1ae2b {
  meta:
    description = "datamaliciousorder - file 20151217_8e5530306a72f46bdcc83acbdbd1ae2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe6ae73553460757f4a15117baff228137584fdb83fb267f6af050e2bd531d6b"

  strings:
    $s1  = "pow(Math.cos(759), 2) - 1)));} dOpvKfVHv[PWsYjNRhDgj]++;}PWsYjNRhDgj++;} return ZoAuywqXQjJ}" fullword ascii
    $s2  = "function jpcetfHJINCkvEZlc(wnOot){ZoAuywqXQjJ= '';PWsYjNRhDgj=Math.round((Math.pow(Math.sin(471), 2) + Math.pow(Math.cos(471), 2" ascii
    $s3  = ") - 1));while(true){if (PWsYjNRhDgj >= (1926+636)/427){break;}dOpvKfVHv[PWsYjNRhDgj]=Math.round((Math.pow(Math.sin(853), 2) + Ma" ascii
    $s4  = "th.pow(Math.cos(853), 2) - 1)); while(true) { if(dOpvKfVHv[PWsYjNRhDgj] > wnOot[PWsYjNRhDgj].length-(491+501)/992) { break; } if" ascii
    $s5  = "function jpcetfHJINCkvEZlc(wnOot){ZoAuywqXQjJ= '';PWsYjNRhDgj=Math.round((Math.pow(Math.sin(471), 2) + Math.pow(Math.cos(471), 2" ascii
    $s6  = "JOeYNRwxJMVOHFpSHwsTDUOhryNMFGJVTMo([wnOot[PWsYjNRhDgj][dOpvKfVHv[PWsYjNRhDgj]]], Math.round((Math.pow(Math.sin(759), 2) + Math." ascii
    $s7  = "function iXnQZBB(EKRarQGPbHufobUxubzIAWpsQlJFSpamfNiT) {return !dGkGTGKYjSB(RHTqLQXNypVpXUp(EKRarQGPbHufobUxubzIAWpsQlJFSpamfNiT" ascii
    $s8  = "var h = new Array();h[0]=[];h[0][0]='d';h[0][1]='a';h[0][2]='d';h[0][3]='a';h[0][4]='46';h[0][5]='3d';h[0][6]='42';h[0][7]='14';" ascii
    $s9  = "function pxAytGNafuTbuFmWadIJOeYNRwxJMVOHFpSHwsTDUOhryNMFGJVTMo(IkpeVuESUwJKO,ctrqoBaXGyUsxO){ return okYbBpM[gMmUnNYm[nzcgL(Ikp" ascii
    $s10 = "function pxAytGNafuTbuFmWadIJOeYNRwxJMVOHFpSHwsTDUOhryNMFGJVTMo(IkpeVuESUwJKO,ctrqoBaXGyUsxO){ return okYbBpM[gMmUnNYm[nzcgL(Ikp" ascii
    $s11 = "function z(HiLMjZjVphSv,ujSKNjaHqCVsKk){HiLMjZjVphSv.push(ujSKNjaHqCVsKk);}" fullword ascii
    $s12 = "function ERMNnkGTVnQnzEO(PRifPuhGxGYyLzrDa,eTPiFGfdtnLRmuoWcXVNkcuNNlmqtmhdsy,tPkAaUzDeKIjdDByZJAFHPSYZzvJWkONdxG){eval(PRifPuhG" ascii
    $s13 = "var h = new Array();h[0]=[];h[0][0]='d';h[0][1]='a';h[0][2]='d';h[0][3]='a';h[0][4]='46';h[0][5]='3d';h[0][6]='42';h[0][7]='14';" ascii
    $s14 = "function qkAIgdkwdGAf(ztENLqrvfDPMT) {return isFinite(ztENLqrvfDPMT);}" fullword ascii
    $s15 = "function ERMNnkGTVnQnzEO(PRifPuhGxGYyLzrDa,eTPiFGfdtnLRmuoWcXVNkcuNNlmqtmhdsy,tPkAaUzDeKIjdDByZJAFHPSYZzvJWkONdxG){eval(PRifPuhG" ascii
    $s16 = "function dGkGTGKYjSB(ybKIuQIzpNXTbs) {return isNaN(ybKIuQIzpNXTbs);}" fullword ascii
    $s17 = "function n(zLXcJrnaHkOShY,OMhlQNmuwpbKe,WyaUzQdKxZd) {zLXcJrnaHkOShY[OMhlQNmuwpbKe]=WyaUzQdKxZd;}" fullword ascii
    $s18 = "function EZPwXmLZdssIIgsZN(juzDfvQBSL,epqZukpRBb) {return parseInt(juzDfvQBSL,epqZukpRBb);}" fullword ascii
    $s19 = "function RHTqLQXNypVpXUp(MNXMPyFpQDbXiBSYZsE) {return parseFloat(MNXMPyFpQDbXiBSYZsE);}" fullword ascii
    $s20 = "function iXnQZBB(EKRarQGPbHufobUxubzIAWpsQlJFSpamfNiT) {return !dGkGTGKYjSB(RHTqLQXNypVpXUp(EKRarQGPbHufobUxubzIAWpsQlJFSpamfNiT" ascii

  condition:
    uint16(0) == 0x4d67 and
    8 of them
}