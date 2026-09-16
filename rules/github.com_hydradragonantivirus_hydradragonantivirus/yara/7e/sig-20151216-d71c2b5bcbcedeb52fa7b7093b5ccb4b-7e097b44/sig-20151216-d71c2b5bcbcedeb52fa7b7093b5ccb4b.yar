rule sig_20151216_d71c2b5bcbcedeb52fa7b7093b5ccb4b {
  meta:
    description = "datamaliciousorder - file 20151216_d71c2b5bcbcedeb52fa7b7093b5ccb4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "579e1d868c71022dfe7953f2a7aa9790ef9f617904b1d25c0581242214bf8f97"

  strings:
    $s1  = "function HbrVFNdUKSzfwKhXL(JeuHU){iYiItSlHUAP= '';bKUQbRUdPiB=Math.round((Math.pow(Math.sin(191), 2) + Math.pow(Math.cos(191), 2" ascii
    $s2  = ") - 1));while(true){if (bKUQbRUdPiB >= (18+738)/126){break;}YRDNGBWuG[bKUQbRUdPiB]=Math.round((Math.pow(Math.sin(585), 2) + Math" ascii
    $s3  = "(Math.cos(449), 2) - 1)));} YRDNGBWuG[bKUQbRUdPiB]++;}bKUQbRUdPiB++;} return iYiItSlHUAP}" fullword ascii
    $s4  = ".pow(Math.cos(585), 2) - 1)); while(true) { if(YRDNGBWuG[bKUQbRUdPiB] > JeuHU[bKUQbRUdPiB].length-(567+280)/847) { break; } if (" ascii
    $s5  = "function HbrVFNdUKSzfwKhXL(JeuHU){iYiItSlHUAP= '';bKUQbRUdPiB=Math.round((Math.pow(Math.sin(191), 2) + Math.pow(Math.cos(191), 2" ascii
    $s6  = "function BBYEuQo(XVSsWkeRKjEAlgPIddNZGvjmtiESHLrCvOPt) {return !CxpXWWufhIn(vLCIUwiHFlmZtWw(XVSsWkeRKjEAlgPIddNZGvjmtiESHLrCvOPt" ascii
    $s7  = "var t = new Array();t[0]=[];t[0][0]='d';t[0][1]='a';t[0][2]='d';t[0][3]='a';t[0][4]='46';t[0][5]='3d';t[0][6]='42';t[0][7]='14';" ascii
    $s8  = "function CxpXWWufhIn(PLmwUAsslYVcWg) {return isNaN(PLmwUAsslYVcWg);}" fullword ascii
    $s9  = "var t = new Array();t[0]=[];t[0][0]='d';t[0][1]='a';t[0][2]='d';t[0][3]='a';t[0][4]='46';t[0][5]='3d';t[0][6]='42';t[0][7]='14';" ascii
    $s10 = "function vLCIUwiHFlmZtWw(fbSQqNUVKlfmYnKTinA) {return parseFloat(fbSQqNUVKlfmYnKTinA);}" fullword ascii
    $s11 = "function BBYEuQo(XVSsWkeRKjEAlgPIddNZGvjmtiESHLrCvOPt) {return !CxpXWWufhIn(vLCIUwiHFlmZtWw(XVSsWkeRKjEAlgPIddNZGvjmtiESHLrCvOPt" ascii
    $s12 = "function L(AmpugSBXPrTe,nksIzxpAdOGKSm){AmpugSBXPrTe.push(nksIzxpAdOGKSm);}" fullword ascii
    $s13 = "function SayopCUpnvjpYuOYVraiIQPRHPSByerdFaJIeCdfwVmdRrKbWfSGkC(PindfnulSxpNb,RvrYBWzZpNTcVf){ return SSgdVIz[yLxvDCbl[aChMY(Pin" ascii
    $s14 = "s);return jocOA;}" fullword ascii
    $s15 = "function mrfsdgOfvfhp(AtVpGhyIzVfGU) {return isFinite(AtVpGhyIzVfGU);}" fullword ascii
    $s16 = "function aChMY(bNWpZSckjSN,KZTdzIPkJBxcR,pENJtQNs){bgSv=lhVKdxwpHioDTphAE(bNWpZSckjSN,KZTdzIPkJBxcR);jocOA=bgSv.toString(pENJtQN" ascii
    $s17 = "function BQlrqIQDxPWpaqx(HfWFxatlKwYqAQuIR,rRihMVNPpKiXKojMOFINhVEdtIVWPMZVCK,cNHJLgcnYeiwnnwlFNKgSmIUVRGtvZdIWvW){eval(HfWFxatl" ascii
    $s18 = "function SayopCUpnvjpYuOYVraiIQPRHPSByerdFaJIeCdfwVmdRrKbWfSGkC(PindfnulSxpNb,RvrYBWzZpNTcVf){ return SSgdVIz[yLxvDCbl[aChMY(Pin" ascii
    $s19 = "function aChMY(bNWpZSckjSN,KZTdzIPkJBxcR,pENJtQNs){bgSv=lhVKdxwpHioDTphAE(bNWpZSckjSN,KZTdzIPkJBxcR);jocOA=bgSv.toString(pENJtQN" ascii
    $s20 = "function BQlrqIQDxPWpaqx(HfWFxatlKwYqAQuIR,rRihMVNPpKiXKojMOFINhVEdtIVWPMZVCK,cNHJLgcnYeiwnnwlFNKgSmIUVRGtvZdIWvW){eval(HfWFxatl" ascii

  condition:
    uint16(0) == 0x4c79 and
    8 of them
}