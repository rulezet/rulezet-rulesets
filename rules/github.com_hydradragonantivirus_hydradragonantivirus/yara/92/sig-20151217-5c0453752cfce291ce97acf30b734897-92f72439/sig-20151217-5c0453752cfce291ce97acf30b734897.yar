rule sig_20151217_5c0453752cfce291ce97acf30b734897 {
  meta:
    description = "datamaliciousorder - file 20151217_5c0453752cfce291ce97acf30b734897.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "891a390948c0f602e7d2ba741d52cce0de341e210706ca529c9ee627d0754095"

  strings:
    $s1  = "function eLqUZYVtdyBZLvXGq(Fakjg){ijTKosXLgWV= '';MbDCbRiZFgz=Math.round((Math.pow(Math.sin(610), 2) + Math.pow(Math.cos(610), 2" ascii
    $s2  = ") - 1));while(true){if (MbDCbRiZFgz >= (3204+276)/580){break;}jQfnrgGhZ[MbDCbRiZFgz]=Math.round((Math.pow(Math.sin(918), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(918), 2) - 1)); while(true) { if(jQfnrgGhZ[MbDCbRiZFgz] > Fakjg[MbDCbRiZFgz].length-(788+57)/845) { break; } if " ascii
    $s4  = "(Math.cos(397), 2) - 1)));} jQfnrgGhZ[MbDCbRiZFgz]++;}MbDCbRiZFgz++;} return ijTKosXLgWV}" fullword ascii
    $s5  = "function eLqUZYVtdyBZLvXGq(Fakjg){ijTKosXLgWV= '';MbDCbRiZFgz=Math.round((Math.pow(Math.sin(610), 2) + Math.pow(Math.cos(610), 2" ascii
    $s6  = "function JMDixgt(foIeJEuPWjOpLNOddgTuzGWSUUckTtZDRuiT) {return !cTnzSOIdtBd(dShvrEzTCCfBHCf(foIeJEuPWjOpLNOddgTuzGWSUUckTtZDRuiT" ascii
    $s7  = "var G = new Array();G[0]=[];G[0][0]='d';G[0][1]='a';G[0][2]='d';G[0][3]='a';G[0][4]='46';G[0][5]='3d';G[0][6]='42';G[0][7]='14';" ascii
    $s8  = "function cTnzSOIdtBd(qXVujNuajZMRdA) {return isNaN(qXVujNuajZMRdA);}" fullword ascii
    $s9  = "function dGSce(uKNDWnxeCJE,GQQNyEyWhlRlm,LRacSlvg){WCyf=IvIgeZkRXiJzPLBDN(uKNDWnxeCJE,GQQNyEyWhlRlm);hwXte=WCyf.toString(LRacSlv" ascii
    $s10 = "function JMDixgt(foIeJEuPWjOpLNOddgTuzGWSUUckTtZDRuiT) {return !cTnzSOIdtBd(dShvrEzTCCfBHCf(foIeJEuPWjOpLNOddgTuzGWSUUckTtZDRuiT" ascii
    $s11 = "function YWGnhBwqNvaOfYGWSTINlIxjGxQtQmquqgGYSUZLkRZmqERXIkCLsq(JYJksIEGmCnyF,IAwGSIaOSGKNAv){ return hxqsVYN[nGUyLxlA[dGSce(JYJ" ascii
    $s12 = "g);return hwXte;}" fullword ascii
    $s13 = "function rFKhoFyGGKJJ(ttUYCDdrbgcqe) {return isFinite(ttUYCDdrbgcqe);}" fullword ascii
    $s14 = "function YWGnhBwqNvaOfYGWSTINlIxjGxQtQmquqgGYSUZLkRZmqERXIkCLsq(JYJksIEGmCnyF,IAwGSIaOSGKNAv){ return hxqsVYN[nGUyLxlA[dGSce(JYJ" ascii
    $s15 = "function J(iWMWIwtWcZQnYy,UheGQserudvNo,rhktEhkJMzV) {iWMWIwtWcZQnYy[UheGQserudvNo]=rhktEhkJMzV;}" fullword ascii
    $s16 = "function IvIgeZkRXiJzPLBDN(SPsZjJsyNf,EaxHPqKedV) {return parseInt(SPsZjJsyNf,EaxHPqKedV);}" fullword ascii
    $s17 = "var G = new Array();G[0]=[];G[0][0]='d';G[0][1]='a';G[0][2]='d';G[0][3]='a';G[0][4]='46';G[0][5]='3d';G[0][6]='42';G[0][7]='14';" ascii
    $s18 = "function ETZiQRUWgbENEIx(lgaOAPWLMNGhlWzvk,janJXhTvzWhLeRgtXeRBDnZVlvRoYwxlBI,UGSzfHpbWTSZvlDAgaXwEdyVQXHHoFBAouB){eval(lgaOAPWL" ascii
    $s19 = "function dGSce(uKNDWnxeCJE,GQQNyEyWhlRlm,LRacSlvg){WCyf=IvIgeZkRXiJzPLBDN(uKNDWnxeCJE,GQQNyEyWhlRlm);hwXte=WCyf.toString(LRacSlv" ascii
    $s20 = "function ETZiQRUWgbENEIx(lgaOAPWLMNGhlWzvk,janJXhTvzWhLeRgtXeRBDnZVlvRoYwxlBI,UGSzfHpbWTSZvlDAgaXwEdyVQXHHoFBAouB){eval(lgaOAPWL" ascii

  condition:
    uint16(0) == 0x476e and
    8 of them
}