rule sig_20151217_8136d34cfb663e03d6b7b869349675d8 {
  meta:
    description = "datamaliciousorder - file 20151217_8136d34cfb663e03d6b7b869349675d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2baf58a76ea816778ad343c838c6dd8dfcc40923775ba815cff985aa0b79d0cf"

  strings:
    $s1  = "function mOoHZZuoyUQzQmdEl(tlYXl){WdgpyfocFLC= '';AvKgJCOMArK=Math.round((Math.pow(Math.sin(356), 2) + Math.pow(Math.cos(356), 2" ascii
    $s2  = ") - 1));while(true){if (AvKgJCOMArK >= (4544+958)/917){break;}ZHNrKcIUU[AvKgJCOMArK]=Math.round((Math.pow(Math.sin(156), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(156), 2) - 1)); while(true) { if(ZHNrKcIUU[AvKgJCOMArK] > tlYXl[AvKgJCOMArK].length-(17+893)/910) { break; } if " ascii
    $s4  = "(Math.cos(336), 2) - 1)));} ZHNrKcIUU[AvKgJCOMArK]++;}AvKgJCOMArK++;} return WdgpyfocFLC}" fullword ascii
    $s5  = "function mOoHZZuoyUQzQmdEl(tlYXl){WdgpyfocFLC= '';AvKgJCOMArK=Math.round((Math.pow(Math.sin(356), 2) + Math.pow(Math.cos(356), 2" ascii
    $s6  = "function CqKtDLG(bQTuHFRwOTCcqPoFAbrxmQUwTfewAbHqMdpz) {return !pLIUFKwYciu(thhGEMYsoHCmjBu(bQTuHFRwOTCcqPoFAbrxmQUwTfewAbHqMdpz" ascii
    $s7  = "var c = new Array();c[0]=[];c[0][0]='d';c[0][1]='a';c[0][2]='d';c[0][3]='a';c[0][4]='46';c[0][5]='3d';c[0][6]='42';c[0][7]='14';" ascii
    $s8  = "function r(aabfCLQNpFjd,xMvlngAcXiYbnK){aabfCLQNpFjd.push(xMvlngAcXiYbnK);}" fullword ascii
    $s9  = "var c = new Array();c[0]=[];c[0][0]='d';c[0][1]='a';c[0][2]='d';c[0][3]='a';c[0][4]='46';c[0][5]='3d';c[0][6]='42';c[0][7]='14';" ascii
    $s10 = "function IeDuy(usaFpPqwAGV,hwQFrOhbwyDlb,UGLWCqRw){RGqU=VeYzKXvvNQKrDvhjl(usaFpPqwAGV,hwQFrOhbwyDlb);HWwgK=RGqU.toString(UGLWCqR" ascii
    $s11 = "function CqKtDLG(bQTuHFRwOTCcqPoFAbrxmQUwTfewAbHqMdpz) {return !pLIUFKwYciu(thhGEMYsoHCmjBu(bQTuHFRwOTCcqPoFAbrxmQUwTfewAbHqMdpz" ascii
    $s12 = "function thhGEMYsoHCmjBu(tNvvvqmDJqBGVHDWoGn) {return parseFloat(tNvvvqmDJqBGVHDWoGn);}" fullword ascii
    $s13 = "function H(phsRMvxgBHJDyf,LHffmzMPFmXwU,fwWHTWkgWVD) {phsRMvxgBHJDyf[LHffmzMPFmXwU]=fwWHTWkgWVD;}" fullword ascii
    $s14 = "function VeYzKXvvNQKrDvhjl(ovaMhbBDjf,wSWrtpumuW) {return parseInt(ovaMhbBDjf,wSWrtpumuW);}" fullword ascii
    $s15 = "function ypcXwBAcioNZMwGgbyaQjzOPEIdOnBvOENHJfOBeBlMJvSszCKmBBv(NSoJzfQNpnfFt,aMwRahHCWdSvoG){ return eugvHXT[AayaGxrS[IeDuy(NSo" ascii
    $s16 = "function ypcXwBAcioNZMwGgbyaQjzOPEIdOnBvOENHJfOBeBlMJvSszCKmBBv(NSoJzfQNpnfFt,aMwRahHCWdSvoG){ return eugvHXT[AayaGxrS[IeDuy(NSo" ascii
    $s17 = "function IeDuy(usaFpPqwAGV,hwQFrOhbwyDlb,UGLWCqRw){RGqU=VeYzKXvvNQKrDvhjl(usaFpPqwAGV,hwQFrOhbwyDlb);HWwgK=RGqU.toString(UGLWCqR" ascii
    $s18 = "w);return HWwgK;}" fullword ascii
    $s19 = "function pLIUFKwYciu(lNSfnndLfbddoW) {return isNaN(lNSfnndLfbddoW);}" fullword ascii
    $s20 = "function KNzPRmWaIjVt(yDqBJDCaGIdhn) {return isFinite(yDqBJDCaGIdhn);}" fullword ascii

  condition:
    uint16(0) == 0x6141 and
    8 of them
}