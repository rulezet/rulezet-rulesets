rule sig_20160531_f69ca707748fac9406618554bb8dac6c {
  meta:
    description = "datamaliciousorder - file 20160531_f69ca707748fac9406618554bb8dac6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f308e6536f23e942557b3802aff64108edf559ce14f484aa03c6c015513921bc"

  strings:
    $s1  = "var kWrGJcQYZpy=function(){return WScript.CreateObject(WoaxMPXbuwIccHJlSR[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function TrAiNTjciVaxOXqLoxeWN(ftkpQeExR,DhUAkTNo){return ftkpQeExR.charAt(DhUAkTNo);}" fullword ascii
    $s3  = "function vSknEApVanQDIn(){return kWrGJcQYZpy.ExpandEnvironmentStrings(wwmEFjhNvbrsR())}" fullword ascii
    $s4  = "8 & 0xff;etdNMrxTdQmyvLfRpLUPhTub = IOdMpdj & 0xff;if (ofyLipWExxJL == 64) AzqusMBmSdAFAYtnqLlcfS += El(ozyrfyjlyF);else if (HvQ" ascii
    $s5  = "(dTuIzduyKtaBgG,0x1,0x0)}function iSxrXcViylrTR(sYNjRdAIhqFZ,VrWcbMLXWyqVr,iTRhTWtYtSdTC){var UxXEEfDAcyR=sYNjRdAIhqFZ.createtex" ascii
    $s6  = "(dTuIzduyKtaBgG,0x1,0x0)}function iSxrXcViylrTR(sYNjRdAIhqFZ,VrWcbMLXWyqVr,iTRhTWtYtSdTC){var UxXEEfDAcyR=sYNjRdAIhqFZ.createtex" ascii
    $s7  = "function UiZwKJKBRXA(cCGCFhosue,TyECCiOXkLdgqw,UgVkU){kpQMGGmTD=cCGCFhosue.split(UgVkU);efIoUeiMUY = WoaxMPXbuwIccHJlSR[0];for(J" ascii
    $s8  = "tfile(VrWcbMLXWyqVr,true);UxXEEfDAcyR.WriteLine(iTRhTWtYtSdTC);UxXEEfDAcyR.Close();}" fullword ascii
    $s9  = "function wwmEFjhNvbrsR(){return UiZwKJKBRXA(WoaxMPXbuwIccHJlSR[9],[1,5,7],WoaxMPXbuwIccHJlSR[10]);}" fullword ascii
    $s10 = "function oXAIjCfg(beamEOYYKJHRyoOlzlaoyev,wfqwkB,CIEwWDKIngNii){return String.fromCharCode(beamEOYYKJHRyoOlzlaoyev,wfqwkB,CIEwWD" ascii
    $s11 = "function qcWfkyx(NiXRVjvlicocQ) {var QHAEJGMPYygDDHnaUhOFt = yGuCwhba.join(WoaxMPXbuwIccHJlSR[7]);var ozyrfyjlyF, DvzeunV, etdNM" ascii
    $s12 = "function JFipzwcnkgmAXNSDBxGFn(PijXB,wobgNDNEWOOHeQHl){return String.fromCharCode(PijXB,wobgNDNEWOOHeQHl);}" fullword ascii
    $s13 = "function jmYESGQapRu(){return UiZwKJKBRXA(WoaxMPXbuwIccHJlSR[13],[0,3,6],WoaxMPXbuwIccHJlSR[14]);}" fullword ascii
    $s14 = "AIjCfg(ozyrfyjlyF, DvzeunV, etdNMrxTdQmyvLfRpLUPhTub);} while (wLcJuEikNbNK < NiXRVjvlicocQ.length);return AzqusMBmSdAFAYtnqLlcf" ascii
    $s15 = "function yRSDxUuoA(){return UiZwKJKBRXA(WoaxMPXbuwIccHJlSR[11],[2,4,8,10],WoaxMPXbuwIccHJlSR[12]);}" fullword ascii
    $s16 = "function UiZwKJKBRXA(cCGCFhosue,TyECCiOXkLdgqw,UgVkU){kpQMGGmTD=cCGCFhosue.split(UgVkU);efIoUeiMUY = WoaxMPXbuwIccHJlSR[0];for(J" ascii
    $s17 = "function JuGpvpAswQFnYNsP(WFAyotlwUeBrIuscs,UlISuPGeBsHEYDYrkaavq){return WFAyotlwUeBrIuscs.indexOf(UlISuPGeBsHEYDYrkaavq);}" fullword ascii
    $s18 = "XUlpEBjmalzdwqvden == 64) AzqusMBmSdAFAYtnqLlcfS += JFipzwcnkgmAXNSDBxGFn(ozyrfyjlyF, DvzeunV);else AzqusMBmSdAFAYtnqLlcfS += oX" ascii
    $s19 = "var HrQhozXi=function(){return new ActiveXObject(WoaxMPXbuwIccHJlSR[1]);}();" fullword ascii
    $s20 = "function qcWfkyx(NiXRVjvlicocQ) {var QHAEJGMPYygDDHnaUhOFt = yGuCwhba.join(WoaxMPXbuwIccHJlSR[7]);var ozyrfyjlyF, DvzeunV, etdNM" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}