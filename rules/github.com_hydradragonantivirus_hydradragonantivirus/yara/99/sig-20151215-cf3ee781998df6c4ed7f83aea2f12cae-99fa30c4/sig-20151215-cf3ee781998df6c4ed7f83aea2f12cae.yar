rule sig_20151215_cf3ee781998df6c4ed7f83aea2f12cae {
  meta:
    description = "datamaliciousorder - file 20151215_cf3ee781998df6c4ed7f83aea2f12cae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "989e82ec32006fd40dbd64d0c0398bbdda9139c0af8384a213d194b42b14e40b"

  strings:
    $s1  = "ath.pow(Math.cos(675), 2) - 1)); while(true) { if(SVeowXJIg[ugmhDOBnNJm] > TEgzp[ugmhDOBnNJm].length-(1+144)/145) { break; } if " ascii
    $s2  = "function zuAOFLpowHRIDUfUz(TEgzp){DEqLTtOZaiX= p[1768];for(ugmhDOBnNJm=Math.round((Math.pow(Math.sin(514), 2) + Math.pow(Math.co" ascii
    $s3  = "w(Math.cos(842), 2) - 1)));} SVeowXJIg[ugmhDOBnNJm]++;}} return DEqLTtOZaiX}" fullword ascii
    $s4  = "function zuAOFLpowHRIDUfUz(TEgzp){DEqLTtOZaiX= p[1768];for(ugmhDOBnNJm=Math.round((Math.pow(Math.sin(514), 2) + Math.pow(Math.co" ascii
    $s5  = "sFnu)) {return (String.fromCharCode(xKOUuiWVWMBUsFnu) + String.fromCharCode((20382+746)/278));}}" fullword ascii
    $s6  = "function J(aOMjnDMleCnu,TxcCQtMrBLqrgN){aOMjnDMleCnu.push(TxcCQtMrBLqrgN);}function X3(xKOUuiWVWMBUsFnu){if(vHIHjxB(xKOUuiWVWMBU" ascii
    $s7  = "function vHIHjxB(qZbqdngegJFXIhoMfGbsVAhemXhQxGsIfIMb) {return !isNaN(parseFloat(qZbqdngegJFXIhoMfGbsVAhemXhQxGsIfIMb)) && isFin" ascii
    $s8  = "function vHIHjxB(qZbqdngegJFXIhoMfGbsVAhemXhQxGsIfIMb) {return !isNaN(parseFloat(qZbqdngegJFXIhoMfGbsVAhemXhQxGsIfIMb)) && isFin" ascii
    $s9  = "var p=new Array();" fullword ascii
    $s10 = "function rghTDItCPUIYnDR(votcnTkGYWxxEumkm){eval(votcnTkGYWxxEumkm)}" fullword ascii
    $s11 = "function PRjjnfEgicmEWbxgKvgKwvqOmdMShjShNbfXAJLXggwGfzupuKfbqe(RNSLSePefEiZK,QbHYhjcUsYvwTs){ return KjCqsuK[pKDIplne[VQyeA(RNS" ascii
    $s12 = "function J(aOMjnDMleCnu,TxcCQtMrBLqrgN){aOMjnDMleCnu.push(TxcCQtMrBLqrgN);}function X3(xKOUuiWVWMBUsFnu){if(vHIHjxB(xKOUuiWVWMBU" ascii
    $s13 = "function VQyeA(vFDyvMKXMeE,uSOVWNfizqxJN,prVOLEtn){DYsx=parseInt(vFDyvMKXMeE,uSOVWNfizqxJN);ckytQ=DYsx.toString(prVOLEtn);return" ascii
    $s14 = "function kGHHILzQbjf(TVPdwNqI,OcSjFQ){return TVPdwNqI.split(OcSjFQ)}" fullword ascii
    $s15 = " ckytQ;}function rghTDItCPUIYnDR(votcnTkGYWxxEumkm,SwtOIdsFQRUJNhoqPJGMtzUvfSeUSHutjM,ILDkKUJNFmXFADujyZTwLbIeSbZLzOzycNL){eval(" ascii
    $s16 = "function PRjjnfEgicmEWbxgKvgKwvqOmdMShjShNbfXAJLXggwGfzupuKfbqe(RNSLSePefEiZK,QbHYhjcUsYvwTs){ return KjCqsuK[pKDIplne[VQyeA(RNS" ascii
    $s17 = "function VQyeA(vFDyvMKXMeE,uSOVWNfizqxJN,prVOLEtn){DYsx=parseInt(vFDyvMKXMeE,uSOVWNfizqxJN);ckytQ=DYsx.toString(prVOLEtn);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}