rule sig_20151210_17eb1db2338389c6f895c7fcf7bb2869 {
  meta:
    description = "datamaliciousorder - file 20151210_17eb1db2338389c6f895c7fcf7bb2869.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "323250267f09ca418c2664ff3877a089f60afe93b2b29ee6f6539f24e430d38a"

  strings:
    $s1  = "function mYjgyOZydZT(rSPYYntk,TQYEkd){return rSPYYntk.split(TQYEkd)}" fullword ascii
    $s2  = "function YTGqgTE(rnTSAjLIJsCYnlAewcfXyZPONThQQUhLqAnU) {return !isNaN(parseFloat(rnTSAjLIJsCYnlAewcfXyZPONThQQUhLqAnU)) && isFin" ascii
    $s3  = "function YTGqgTE(rnTSAjLIJsCYnlAewcfXyZPONThQQUhLqAnU) {return !isNaN(parseFloat(rnTSAjLIJsCYnlAewcfXyZPONThQQUhLqAnU)) && isFin" ascii
    $s4  = "function TdplNdUDbnQNApEBxZlckGlPznPiUKHASRLNyKLKJbZTmuaLTdzRGD(TzKryHAJkVvPl,rapOeLMHfAudpi){ return PpoSjYFzuoPKr[nHciq(TzKryH" ascii
    $s5  = "function rNxBlWHKlaKFtyoJu(QYdlb){lcgifqXOlqQ= '';for(qKvGGUxXjVa=(-768+768)/299; qKvGGUxXjVa < (7+157)/82; qKvGGUxXjVa++) {ErbD" ascii
    $s6  = "function rNxBlWHKlaKFtyoJu(QYdlb){lcgifqXOlqQ= '';for(qKvGGUxXjVa=(-768+768)/299; qKvGGUxXjVa < (7+157)/82; qKvGGUxXjVa++) {ErbD" ascii
    $s7  = "bBjbqhP=(-642+642)/57;while(true){if(bBjbqhP>=(48945+847)/389){break;}PpoSjYFzuoPKr[bBjbqhP]=String.fromCharCode(bBjbqhP);bBjbqh" ascii
    $s8  = "bBjbqhP=(-642+642)/57;while(true){if(bBjbqhP>=(48945+847)/389){break;}PpoSjYFzuoPKr[bBjbqhP]=String.fromCharCode(bBjbqhP);bBjbqh" ascii
    $s9  = "function nHciq(sbnvClOyClO,drpTMxABBQkpF,QNpbJiQF){akgy=parseInt(sbnvClOyClO,drpTMxABBQkpF);AOcwK=akgy.toString(QNpbJiQF);return" ascii
    $s10 = "turn lcgifqXOlqQ}" fullword ascii
    $s11 = "function TdplNdUDbnQNApEBxZlckGlPznPiUKHASRLNyKLKJbZTmuaLTdzRGD(TzKryHAJkVvPl,rapOeLMHfAudpi){ return PpoSjYFzuoPKr[nHciq(TzKryH" ascii
    $s12 = "ASePo[qKvGGUxXjVa]=(-177+177)/324; while(true) { if(ErbDASePo[qKvGGUxXjVa] > QYdlb[qKvGGUxXjVa].length-(3+7)/10) { break; } if (" ascii
    $s13 = "function nHciq(sbnvClOyClO,drpTMxABBQkpF,QNpbJiQF){akgy=parseInt(sbnvClOyClO,drpTMxABBQkpF);AOcwK=akgy.toString(QNpbJiQF);return" ascii
    $s14 = " AOcwK;}function EmPoBJZnlRmdWPV(UjciMnGWcRlktzZwQ){eval(UjciMnGWcRlktzZwQ)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}