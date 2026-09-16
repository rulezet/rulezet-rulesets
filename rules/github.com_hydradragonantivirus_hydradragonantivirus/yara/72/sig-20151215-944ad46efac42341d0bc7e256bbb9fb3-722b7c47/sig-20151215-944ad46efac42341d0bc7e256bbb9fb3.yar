rule sig_20151215_944ad46efac42341d0bc7e256bbb9fb3 {
  meta:
    description = "datamaliciousorder - file 20151215_944ad46efac42341d0bc7e256bbb9fb3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdb11f7929fc23e0f3b71b0c581bb819d627dfc907f7b23863759aba45ef9cdb"

  strings:
    $s1  = "ath.pow(Math.cos(129), 2) - 1)); while(true) { if(zGloHmCYO[bFXuFSAxqRq] > rcFWP[bFXuFSAxqRq].length-(45+138)/183) { break; } if" ascii
    $s2  = "ow(Math.cos(839), 2) - 1)));} zGloHmCYO[bFXuFSAxqRq]++;}} return jWZmIYxiiUR}" fullword ascii
    $s3  = "function NfUxzcwvmjGIahgWD(rcFWP){jWZmIYxiiUR= I[1794];for(bFXuFSAxqRq=Math.round((Math.pow(Math.sin(938), 2) + Math.pow(Math.co" ascii
    $s4  = "function NfUxzcwvmjGIahgWD(rcFWP){jWZmIYxiiUR= I[1794];for(bFXuFSAxqRq=Math.round((Math.pow(Math.sin(938), 2) + Math.pow(Math.co" ascii
    $s5  = "function A(lgILaVPPQjUM,tBUmIJICVFVXHd){lgILaVPPQjUM.push(tBUmIJICVFVXHd);}function L7(tWCSrXOmFYGFnnXk){if(LyhjqmH(tWCSrXOmFYGF" ascii
    $s6  = "nnXk)) {return (String.fromCharCode(tWCSrXOmFYGFnnXk) + String.fromCharCode((12861+249)/230));}}" fullword ascii
    $s7  = "function LyhjqmH(aBeFutwWEPoCwBSSTvkcqqHBHiIJhokpDzkj) {return !isNaN(parseFloat(aBeFutwWEPoCwBSSTvkcqqHBHiIJhokpDzkj)) && isFin" ascii
    $s8  = "function LyhjqmH(aBeFutwWEPoCwBSSTvkcqqHBHiIJhokpDzkj) {return !isNaN(parseFloat(aBeFutwWEPoCwBSSTvkcqqHBHiIJhokpDzkj)) && isFin" ascii
    $s9  = "function HvEnKINrXmxGylgXqcYJgQryfEEJMiCGDHYdiQrTxwLCsvVaJHNyLm(OtuIvmsjxVKNA,cxIFeivZSVQipF){ return EJHPeTP[dnGgFtHE[wgDEl(Otu" ascii
    $s10 = "function A(lgILaVPPQjUM,tBUmIJICVFVXHd){lgILaVPPQjUM.push(tBUmIJICVFVXHd);}function L7(tWCSrXOmFYGFnnXk){if(LyhjqmH(tWCSrXOmFYGF" ascii
    $s11 = "function JMMuxnlQzwHlGLh(oGestnqwRwareIrGn){eval(oGestnqwRwareIrGn)}" fullword ascii
    $s12 = "function JXPfownTDak(tnxCQOzT,FOJwjj){return tnxCQOzT.split(FOJwjj)}" fullword ascii
    $s13 = " czBMj;}function JMMuxnlQzwHlGLh(oGestnqwRwareIrGn,wVdcMlqWzpSqKkLxctkYjbqXDNQmqBrDLF,NQDzgKqbQagpEASLlcIYHlQmKYWjhSRvuEb){eval(" ascii
    $s14 = "function wgDEl(nSPmFhViCNy,znYEfOiEMKFvP,LauFskof){dino=parseInt(nSPmFhViCNy,znYEfOiEMKFvP);czBMj=dino.toString(LauFskof);return" ascii
    $s15 = "function HvEnKINrXmxGylgXqcYJgQryfEEJMiCGDHYdiQrTxwLCsvVaJHNyLm(OtuIvmsjxVKNA,cxIFeivZSVQipF){ return EJHPeTP[dnGgFtHE[wgDEl(Otu" ascii
    $s16 = "function wgDEl(nSPmFhViCNy,znYEfOiEMKFvP,LauFskof){dino=parseInt(nSPmFhViCNy,znYEfOiEMKFvP);czBMj=dino.toString(LauFskof);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}