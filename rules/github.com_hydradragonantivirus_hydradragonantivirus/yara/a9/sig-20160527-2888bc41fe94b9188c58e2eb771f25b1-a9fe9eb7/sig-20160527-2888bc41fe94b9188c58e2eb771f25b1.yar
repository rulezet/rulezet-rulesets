rule sig_20160527_2888bc41fe94b9188c58e2eb771f25b1 {
  meta:
    description = "datamaliciousorder - file 20160527_2888bc41fe94b9188c58e2eb771f25b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6bebfa0b0b3ca6151d494eb31bcfbc671327500339ff7c32618057eec3e307e"

  strings:
    $s1  = "function CGgByEpB() {return WScript;}function mLxrc(){return BXaVbjZRbovl.ExpandEnvironmentStrings(FaoaaR())}" fullword ascii
    $s2  = "function ojfwDTudSCP(hoTDOS,AssjyudDG){return hoTDOS.charAt(AssjyudDG);}" fullword ascii
    $s3  = "function WVAQbzarQ(eLVdt,jYxUlEWQ,oVORvzczBbxk){qYSkDxdYrJsf=eLVdt.split(oVORvzczBbxk);FTEkE = xLllD[14];for(pLBGzKzXmJ=0;pLBGzK" ascii
    $s4  = "function LIeWt(mPakeCdKMrgVw) {var RYcRXlWqrBalCT = nMHKXkBqtXnGiXjvWs.join(xLllD[6]);var NtVTmqrnRv, OOwxWsYuDhFHXlkWXdmbkY, GZ" ascii
    $s5  = "function tuLsMRWNuskNDpeAlQxZKjm(hcXQN,sUKZbKbaApsH){return hcXQN.indexOf(sUKZbKbaApsH);}" fullword ascii
    $s6  = "function LIeWt(mPakeCdKMrgVw) {var RYcRXlWqrBalCT = nMHKXkBqtXnGiXjvWs.join(xLllD[6]);var NtVTmqrnRv, OOwxWsYuDhFHXlkWXdmbkY, GZ" ascii
    $s7  = "function SfmaLLoH(cCbOwecBwyMI,bnCbrutnwXAtQoKEf,FuKNNGAejCzlUFHMQZyUemrI){return String.fromCharCode(cCbOwecBwyMI,bnCbrutnwXAtQ" ascii
    $s8  = "function T(MrFxuJhCqFBATASaGzeTAkwf){return String.fromCharCode(MrFxuJhCqFBATASaGzeTAkwf);}" fullword ascii
    $s9  = "function SfmaLLoH(cCbOwecBwyMI,bnCbrutnwXAtQoKEf,FuKNNGAejCzlUFHMQZyUemrI){return String.fromCharCode(cCbOwecBwyMI,bnCbrutnwXAtQ" ascii
    $s10 = "var qBHkZLY=function(){return new ActiveXObject(xLllD[0]);}();" fullword ascii
    $s11 = "function WVAQbzarQ(eLVdt,jYxUlEWQ,oVORvzczBbxk){qYSkDxdYrJsf=eLVdt.split(oVORvzczBbxk);FTEkE = xLllD[14];for(pLBGzKzXmJ=0;pLBGzK" ascii
    $s12 = "function dbLurITalLI(){return WVAQbzarQ(xLllD[12],[0,3,6],xLllD[13]);}" fullword ascii
    $s13 = "J += SfmaLLoH(NtVTmqrnRv, OOwxWsYuDhFHXlkWXdmbkY, GZARHQUmLOTaIzVUNbzyq);} while (YcWRaitslFYOqdZCncuzrkHB < mPakeCdKMrgVw.lengt" ascii
    $s14 = "function lbKsC(mrBEdaQDnpEAa,AcJHAiiwlhowdAP){return String.fromCharCode(mrBEdaQDnpEAa,AcJHAiiwlhowdAP);}" fullword ascii
    $s15 = "function sWqucrnxRS(oZkOSZ,pOpGAmayNk) {var TqIHdDKzWE=[xLllD[15]];oZkOSZ[TqIHdDKzWE[0]](pOpGAmayNk,0x1,0x0)}" fullword ascii
    $s16 = "var YsyLTsVkGfpoeA = qBHkZLY.createtextfile(BXaVbjZRbovl.ExpandEnvironmentStrings(xLllD[2]+xLllD[3])+String.fromCharCode(92)+xLl" ascii
    $s17 = "WTJVJ += T(NtVTmqrnRv);else if (QvHKeJ == 64) vTwuOfRSaIOWTJVJ += lbKsC(NtVTmqrnRv, OOwxWsYuDhFHXlkWXdmbkY);else vTwuOfRSaIOWTJV" ascii
    $s18 = "push(\"D\");nMHKXkBqtXnGiXjvWs.push(\"3\");nMHKXkBqtXnGiXjvWs.push(\"E\");nMHKXkBqtXnGiXjvWs.push(\"F\");nMHKXkBqtXnGiXjvWs.push" ascii
    $s19 = "var BXaVbjZRbovl=function(){return CGgByEpB().CreateObject(xLllD[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s20 = "function PUPpW(){return WVAQbzarQ(xLllD[10],[2,4,8,10],xLllD[11]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}