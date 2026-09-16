rule sig_20151216_b954311a5cba9fde8578f40eafc0e6cf {
  meta:
    description = "datamaliciousorder - file 20151216_b954311a5cba9fde8578f40eafc0e6cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46d8a8283be7717dcfcd3dc63604e5bb06c63b173003f035d7069aaff017a195"

  strings:
    $s1  = "ath.cos(772), 2) - 1)));} YFRtefwKs[USlwVZQyuLr]++;}USlwVZQyuLr++;} return tKGuWwjxGZx}" fullword ascii
    $s2  = ".pow(Math.cos(204), 2) - 1)); while(true) { if(YFRtefwKs[USlwVZQyuLr] > uUSLb[USlwVZQyuLr].length-(-9+749)/740) { break; } if (h" ascii
    $s3  = ") - 1));while(true){if (USlwVZQyuLr >= (887+91)/163){break;}YFRtefwKs[USlwVZQyuLr]=Math.round((Math.pow(Math.sin(204), 2) + Math" ascii
    $s4  = "function YsOjyGHsKgPGnSUaS(uUSLb){tKGuWwjxGZx= '';USlwVZQyuLr=Math.round((Math.pow(Math.sin(699), 2) + Math.pow(Math.cos(699), 2" ascii
    $s5  = "function YsOjyGHsKgPGnSUaS(uUSLb){tKGuWwjxGZx= '';USlwVZQyuLr=Math.round((Math.pow(Math.sin(699), 2) + Math.pow(Math.cos(699), 2" ascii
    $s6  = "function hpuufmZ(SQzEVLExPUAtyEjzkvAcfuLNKZhbgkKzhjru) {return !yzenPmPIzuC(BWepRcKotfmxxNl(SQzEVLExPUAtyEjzkvAcfuLNKZhbgkKzhjru" ascii
    $s7  = "var U = new Array();U[0]=[];U[0][0]='d';U[0][1]='a';U[0][2]='d';U[0][3]='a';U[0][4]='46';U[0][5]='3d';U[0][6]='42';U[0][7]='14';" ascii
    $s8  = "t);return kqDvv;}" fullword ascii
    $s9  = "function mPVXR(QQxAYYzsfcz,FjUtvILWsviUr,EImLjsEt){jghm=PqXkCymwRYXNnmobM(QQxAYYzsfcz,FjUtvILWsviUr);kqDvv=jghm.toString(EImLjsE" ascii
    $s10 = "function v(pjIYBWVEijlkjg,MuJUqljoNpZNg,HIwoXtFnQNc) {pjIYBWVEijlkjg[MuJUqljoNpZNg]=HIwoXtFnQNc;}" fullword ascii
    $s11 = "function E(iriEhqvSQaHh,otmcUdRceSEZTn){iriEhqvSQaHh.push(otmcUdRceSEZTn);}" fullword ascii
    $s12 = "function PqXkCymwRYXNnmobM(knrjPxyBJr,FGVlGUToVx) {return parseInt(knrjPxyBJr,FGVlGUToVx);}" fullword ascii
    $s13 = "function yzenPmPIzuC(qCDCquCzSnZSiF) {return isNaN(qCDCquCzSnZSiF);}" fullword ascii
    $s14 = "function ZwrIkxMwyenYkHYIOhtkGgfkjYaPunHUanHbrLINzrQldsgmkXGHDs(QSztdQPxgnRJU,SJzJOINzkfFomF){ return EkUUBOq[sKpovbfM[mPVXR(QSz" ascii
    $s15 = "function qmxpnJhtGaCwjLH(hsheTsOIzyOSgfbDd,FNZduWESknGPXwAbbBUubWFWKTJfebWRXw,LkaWJcnKtTrKmfcNlsCKBeywtjvbWWATDdB){eval(hsheTsOI" ascii
    $s16 = "function hpuufmZ(SQzEVLExPUAtyEjzkvAcfuLNKZhbgkKzhjru) {return !yzenPmPIzuC(BWepRcKotfmxxNl(SQzEVLExPUAtyEjzkvAcfuLNKZhbgkKzhjru" ascii
    $s17 = "function ZwrIkxMwyenYkHYIOhtkGgfkjYaPunHUanHbrLINzrQldsgmkXGHDs(QSztdQPxgnRJU,SJzJOINzkfFomF){ return EkUUBOq[sKpovbfM[mPVXR(QSz" ascii
    $s18 = "var U = new Array();U[0]=[];U[0][0]='d';U[0][1]='a';U[0][2]='d';U[0][3]='a';U[0][4]='46';U[0][5]='3d';U[0][6]='42';U[0][7]='14';" ascii
    $s19 = "function qgtZATpuKnnm(joukaDNDhgxLY) {return isFinite(joukaDNDhgxLY);}" fullword ascii
    $s20 = "function qmxpnJhtGaCwjLH(hsheTsOIzyOSgfbDd,FNZduWESknGPXwAbbBUubWFWKTJfebWRXw,LkaWJcnKtTrKmfcNlsCKBeywtjvbWWATDdB){eval(hsheTsOI" ascii

  condition:
    uint16(0) == 0x4b73 and
    8 of them
}