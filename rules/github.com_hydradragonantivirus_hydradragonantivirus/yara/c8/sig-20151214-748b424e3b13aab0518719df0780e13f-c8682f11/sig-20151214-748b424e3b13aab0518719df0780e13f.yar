rule sig_20151214_748b424e3b13aab0518719df0780e13f {
  meta:
    description = "datamaliciousorder - file 20151214_748b424e3b13aab0518719df0780e13f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f7f6c8bd382833e48341333d4152cfc9dfbd367ad0d60bf2f80251db4c5ce8b"

  strings:
    $s1  = "ow(Math.cos(74), 2) - 1)));} ueLHwQCWn[mtmNcifPOmh]++;}} return LmoGCdlfnik}" fullword ascii
    $s2  = "th.pow(Math.cos(69), 2) - 1)); while(true) { if(ueLHwQCWn[mtmNcifPOmh] > RoMkW[mtmNcifPOmh].length-(-185+503)/318) { break; } if" ascii
    $s3  = "function uYTkLzpYxnCjdvRUJ(RoMkW){LmoGCdlfnik= M[1760];for(mtmNcifPOmh=Math.round((Math.pow(Math.sin(519), 2) + Math.pow(Math.co" ascii
    $s4  = "function uYTkLzpYxnCjdvRUJ(RoMkW){LmoGCdlfnik= M[1760];for(mtmNcifPOmh=Math.round((Math.pow(Math.sin(519), 2) + Math.pow(Math.co" ascii
    $s5  = "xJAJ)) {return (String.fromCharCode(KCrGremjUFhpxJAJ) + String.fromCharCode((25122+510)/712));}}" fullword ascii
    $s6  = "function j(FgVKaqGybMXA,LLqXtESJUrEfVv){FgVKaqGybMXA.push(LLqXtESJUrEfVv);}function x3(KCrGremjUFhpxJAJ){if(wwJfIEF(KCrGremjUFhp" ascii
    $s7  = "function wwJfIEF(QKNnNdQysmjPiPGceznmKdsZMIoFyeeWCBVu) {return !isNaN(parseFloat(QKNnNdQysmjPiPGceznmKdsZMIoFyeeWCBVu)) && isFin" ascii
    $s8  = "function wwJfIEF(QKNnNdQysmjPiPGceznmKdsZMIoFyeeWCBVu) {return !isNaN(parseFloat(QKNnNdQysmjPiPGceznmKdsZMIoFyeeWCBVu)) && isFin" ascii
    $s9  = "function RHRAURGTYGJjRCT(fvTjXeFleWoxsTwAG){eval(fvTjXeFleWoxsTwAG)}" fullword ascii
    $s10 = "function tCNBMCKhXGutAhWZmXjCRiJPpZxfmBxyrbsVWgLnuPcWeXRaOBfnwB(uNWPPpgxTYxUI,BrITldGhRYSpnd){ return ytTddin[iGjJCJPx[ielrX(uNW" ascii
    $s11 = "function ielrX(fjSRNfJPEkL,SERLZBNxdhXLB,QwGIIujM){FNwI=parseInt(fjSRNfJPEkL,SERLZBNxdhXLB);DFilc=FNwI.toString(QwGIIujM);return" ascii
    $s12 = "function bjoOdYwkfsK(lsSkmTMF,knHhMX){return lsSkmTMF.split(knHhMX)}" fullword ascii
    $s13 = "var M=new Array();" fullword ascii
    $s14 = "function ielrX(fjSRNfJPEkL,SERLZBNxdhXLB,QwGIIujM){FNwI=parseInt(fjSRNfJPEkL,SERLZBNxdhXLB);DFilc=FNwI.toString(QwGIIujM);return" ascii
    $s15 = " DFilc;}function RHRAURGTYGJjRCT(fvTjXeFleWoxsTwAG,zwXsyCrRIEKkkNURjhLaDVRetsGqBpeEPz,egsolznDmWZmgzelntgddPkOHGsRNLFkDMG){eval(" ascii
    $s16 = "function tCNBMCKhXGutAhWZmXjCRiJPpZxfmBxyrbsVWgLnuPcWeXRaOBfnwB(uNWPPpgxTYxUI,BrITldGhRYSpnd){ return ytTddin[iGjJCJPx[ielrX(uNW" ascii
    $s17 = "function j(FgVKaqGybMXA,LLqXtESJUrEfVv){FgVKaqGybMXA.push(LLqXtESJUrEfVv);}function x3(KCrGremjUFhpxJAJ){if(wwJfIEF(KCrGremjUFhp" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}