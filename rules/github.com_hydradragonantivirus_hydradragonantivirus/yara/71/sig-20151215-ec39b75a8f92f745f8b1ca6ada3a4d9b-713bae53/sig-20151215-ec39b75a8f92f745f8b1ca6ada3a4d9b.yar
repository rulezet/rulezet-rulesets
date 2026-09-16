rule sig_20151215_ec39b75a8f92f745f8b1ca6ada3a4d9b {
  meta:
    description = "datamaliciousorder - file 20151215_ec39b75a8f92f745f8b1ca6ada3a4d9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f2ae96d8ec3fa2fd5a48a4415c085ce4d55de4c9b07e9c06fee469a611c3b3e"

  strings:
    $s1  = "ath.cos(759), 2) - 1)));} kXBSsjWzp[bIubmzZHahK]++;}} return GhIzUQIelxv}" fullword ascii
    $s2  = "(47), 2) - 1)); bIubmzZHahK < (-198+210)/6; bIubmzZHahK++) {kXBSsjWzp[bIubmzZHahK]=Math.round((Math.pow(Math.sin(177), 2) + Math" ascii
    $s3  = "function rlfzaxYtkoygwAimG(kBtWE){GhIzUQIelxv= Q[1774];for(bIubmzZHahK=Math.round((Math.pow(Math.sin(47), 2) + Math.pow(Math.cos" ascii
    $s4  = ".pow(Math.cos(177), 2) - 1)); while(true) { if(kXBSsjWzp[bIubmzZHahK] > kBtWE[bIubmzZHahK].length-(74+446)/520) { break; } if (P" ascii
    $s5  = "function rlfzaxYtkoygwAimG(kBtWE){GhIzUQIelxv= Q[1774];for(bIubmzZHahK=Math.round((Math.pow(Math.sin(47), 2) + Math.pow(Math.cos" ascii
    $s6  = "function M(elLIFdVrThFg,qydddmhdGXFdiS){elLIFdVrThFg.push(qydddmhdGXFdiS);}function P1(bNPZUhhZjQAtAzrm){if(PkTRmgX(bNPZUhhZjQAt" ascii
    $s7  = "Azrm)) {return (String.fromCharCode(bNPZUhhZjQAtAzrm) + String.fromCharCode((42515+449)/934));}}" fullword ascii
    $s8  = "function PkTRmgX(pqnOAUssCGkPJJstdZFnQUAmVyiNVrXVnqDy) {return !isNaN(parseFloat(pqnOAUssCGkPJJstdZFnQUAmVyiNVrXVnqDy)) && isFin" ascii
    $s9  = "function PkTRmgX(pqnOAUssCGkPJJstdZFnQUAmVyiNVrXVnqDy) {return !isNaN(parseFloat(pqnOAUssCGkPJJstdZFnQUAmVyiNVrXVnqDy)) && isFin" ascii
    $s10 = "function ZkOsmjnEEsyxWsNTdsFgqZeaFxqqkTSpSObTphclqSBnGGPPiGMKqZ(TAwKqaNBQQlwq,sXwwfoODiJrVOp){ return DKPhYVW[btnykufW[SeUoM(TAw" ascii
    $s11 = "function cbOFWGZHrPv(HOHUvOqO,ZvxEeo){return HOHUvOqO.split(ZvxEeo)}" fullword ascii
    $s12 = "function M(elLIFdVrThFg,qydddmhdGXFdiS){elLIFdVrThFg.push(qydddmhdGXFdiS);}function P1(bNPZUhhZjQAtAzrm){if(PkTRmgX(bNPZUhhZjQAt" ascii
    $s13 = "var Q=new Array();" fullword ascii
    $s14 = "function ZkOsmjnEEsyxWsNTdsFgqZeaFxqqkTSpSObTphclqSBnGGPPiGMKqZ(TAwKqaNBQQlwq,sXwwfoODiJrVOp){ return DKPhYVW[btnykufW[SeUoM(TAw" ascii
    $s15 = "function SeUoM(hmiDNMEoNLD,GDVZCfiZgFQPZ,YPMuduAv){wazM=parseInt(hmiDNMEoNLD,GDVZCfiZgFQPZ);gyxBI=wazM.toString(YPMuduAv);return" ascii
    $s16 = "function SeUoM(hmiDNMEoNLD,GDVZCfiZgFQPZ,YPMuduAv){wazM=parseInt(hmiDNMEoNLD,GDVZCfiZgFQPZ);gyxBI=wazM.toString(YPMuduAv);return" ascii
    $s17 = " gyxBI;}function rebKUTyrCYAbflv(NIBSqqwJgsDaqWEuE,xaYKzXBjhyRNCtKFmDxDjGgbOMBHiZFRbD,GusSYUYnUmLJnApphOnXHCltvrfLqWeCqwY){eval(" ascii
    $s18 = "function rebKUTyrCYAbflv(NIBSqqwJgsDaqWEuE){eval(NIBSqqwJgsDaqWEuE)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}