rule sig_20151217_e26b4d4533e5de7f1d60f90fe0a6cb22 {
  meta:
    description = "datamaliciousorder - file 20151217_e26b4d4533e5de7f1d60f90fe0a6cb22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0afe782d9a177b8fe83bb2424553ad04dfdb61d0499cdf1869ef6bba74b60ebf"

  strings:
    $s1  = "function kIPtuKUjqeyzyTjjY(eAeiP){YrGgTDdIKLE= '';NLAsTQgdRRq=Math.round((Math.pow(Math.sin(336), 2) + Math.pow(Math.cos(336), 2" ascii
    $s2  = "pow(Math.cos(7), 2) - 1)); while(true) { if(FAkpEssch[NLAsTQgdRRq] > eAeiP[NLAsTQgdRRq].length-(680+232)/912) { break; } if (ffy" ascii
    $s3  = ") - 1));while(true){if (NLAsTQgdRRq >= (4490+46)/756){break;}FAkpEssch[NLAsTQgdRRq]=Math.round((Math.pow(Math.sin(7), 2) + Math." ascii
    $s4  = "th.cos(610), 2) - 1)));} FAkpEssch[NLAsTQgdRRq]++;}NLAsTQgdRRq++;} return YrGgTDdIKLE}" fullword ascii
    $s5  = "function kIPtuKUjqeyzyTjjY(eAeiP){YrGgTDdIKLE= '';NLAsTQgdRRq=Math.round((Math.pow(Math.sin(336), 2) + Math.pow(Math.cos(336), 2" ascii
    $s6  = "function WizHLAbczRqAXPeylVaADVEAYtZeGethocNSgtolQvcDkCusZtzLvw(FfZZHNaBaltjP,DYncYgUHShhniQ){ return FjBwcwa[nxGThkWt[LProg(FfZ" ascii
    $s7  = "function WizHLAbczRqAXPeylVaADVEAYtZeGethocNSgtolQvcDkCusZtzLvw(FfZZHNaBaltjP,DYncYgUHShhniQ){ return FjBwcwa[nxGThkWt[LProg(FfZ" ascii
    $s8  = "function ffyJXqQ(uJjMoSQjLwTHqKelvfJuMxYiQOvEunONlxQj) {return !RDkrngsMLiX(fcDMuiGFPZJqSiz(uJjMoSQjLwTHqKelvfJuMxYiQOvEunONlxQj" ascii
    $s9  = "var A = new Array();A[0]=[];A[0][0]='d';A[0][1]='a';A[0][2]='d';A[0][3]='a';A[0][4]='46';A[0][5]='3d';A[0][6]='42';A[0][7]='14';" ascii
    $s10 = "function AkriYhsSXPde(RzqJhLKNTWQAH) {return isFinite(RzqJhLKNTWQAH);}" fullword ascii
    $s11 = "M);return vYfQx;}" fullword ascii
    $s12 = "function fcDMuiGFPZJqSiz(PpwcjHaJTwQGIBBDxoH) {return parseFloat(PpwcjHaJTwQGIBBDxoH);}" fullword ascii
    $s13 = "function i(rrAPiQLKJzZYAP,QhCOwsMXnruEv,nRvxOJXdkMm) {rrAPiQLKJzZYAP[QhCOwsMXnruEv]=nRvxOJXdkMm;}" fullword ascii
    $s14 = "function LProg(WDKkWSfhMDT,sPQPUyYAIeHqB,PnBUwepM){VDuK=kFmHWGoIwvkdbyxcC(WDKkWSfhMDT,sPQPUyYAIeHqB);vYfQx=VDuK.toString(PnBUwep" ascii
    $s15 = ",']','N','X','#','s',',','W','.','@','?','l','X','4','a','R','n','0','s','Y','&','*','7','Z','t','o','D','9','r','[','S',String." ascii
    $s16 = "function aqkvnmbHUdRhUhV(FkPTjDXKWwtWpfYuP,BWsEnkJhUFGtunpAoPsbMhEePvZLxTCqYg,pdBDZaIPZnTelNHPMWUpFzOkdAhVRDtbUev){eval(FkPTjDXK" ascii
    $s17 = "function kFmHWGoIwvkdbyxcC(vXnGnGfQgL,wuITpUGTxO) {return parseInt(vXnGnGfQgL,wuITpUGTxO);}" fullword ascii
    $s18 = "function ffyJXqQ(uJjMoSQjLwTHqKelvfJuMxYiQOvEunONlxQj) {return !RDkrngsMLiX(fcDMuiGFPZJqSiz(uJjMoSQjLwTHqKelvfJuMxYiQOvEunONlxQj" ascii
    $s19 = "var A = new Array();A[0]=[];A[0][0]='d';A[0][1]='a';A[0][2]='d';A[0][3]='a';A[0][4]='46';A[0][5]='3d';A[0][6]='42';A[0][7]='14';" ascii
    $s20 = "function LProg(WDKkWSfhMDT,sPQPUyYAIeHqB,PnBUwepM){VDuK=kFmHWGoIwvkdbyxcC(WDKkWSfhMDT,sPQPUyYAIeHqB);vYfQx=VDuK.toString(PnBUwep" ascii

  condition:
    uint16(0) == 0x786e and
    8 of them
}