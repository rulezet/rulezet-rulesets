rule sig_20160530_a32d0bb88c13fdcabe9262ca89af75d8 {
  meta:
    description = "datamaliciousorder - file 20160530_a32d0bb88c13fdcabe9262ca89af75d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5364607beca1fd2133394280fa0f6f784325189a9579aaadc6ab0cef1578b04"

  strings:
    $s1  = "var KhHoJSUFpTha=function(){return WScript.CreateObject(baxQHWiyO[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function OZrZLHiIafbTns(XQedCT,lzusAq){return XQedCT.charAt(lzusAq);}" fullword ascii
    $s3  = "var vITnlhvRxuoWH = XlmGik.createtextfile(KhHoJSUFpTha.ExpandEnvironmentStrings(baxQHWiyO[3]+baxQHWiyO[4])+String.fromCharCode(9" ascii
    $s4  = "function zUNnNytEuzL(){return rKXDIPn(baxQHWiyO[9],[1,5,7],baxQHWiyO[10]);}" fullword ascii
    $s5  = "function enGDQayzaObLkzR(uZYFVJMi,fwmjW){return String.fromCharCode(uZYFVJMi,fwmjW);}" fullword ascii
    $s6  = "2)+baxQHWiyO[5],true);" fullword ascii
    $s7  = "function JADLQDfe(flhKBlIpGpKvPBwjUaVyXx,jgXOkZaHqzozQWTm,AtBwLEETOWUTKsmMvk){return String.fromCharCode(flhKBlIpGpKvPBwjUaVyXx," ascii
    $s8  = "var XlmGik=function(){return new ActiveXObject(baxQHWiyO[1]);}();" fullword ascii
    $s9  = "function CdEtdDZiYeGW(){return rKXDIPn(baxQHWiyO[13],[0,3,6],baxQHWiyO[14]);}" fullword ascii
    $s10 = "function ziQXreALqXKZ(dpaLFbzR,KILCcjafm) {var wSeEAxWhUE=[baxQHWiyO[15]];dpaLFbzR[wSeEAxWhUE[0]]" fullword ascii
    $s11 = "function YVppyjcfIw(){return KhHoJSUFpTha.ExpandEnvironmentStrings(zUNnNytEuzL())}" fullword ascii
    $s12 = "oPdX=0;wFgEoPdX<IXslxm.length;wFgEoPdX++) {MtNVrG+=zfAiPSYaVDjHm[IXslxm[wFgEoPdX]];}return MtNVrG.substring(3,MtNVrG.length);}" fullword ascii
    $s13 = "function JADLQDfe(flhKBlIpGpKvPBwjUaVyXx,jgXOkZaHqzozQWTm,AtBwLEETOWUTKsmMvk){return String.fromCharCode(flhKBlIpGpKvPBwjUaVyXx," ascii
    $s14 = "function T(QTPcm){return String.fromCharCode(QTPcm);}" fullword ascii
    $s15 = "function kZYsztSDDVHNcFZ(OEwdIqZwHG,UNtyLNPuEYim){return OEwdIqZwHG.indexOf(UNtyLNPuEYim);}" fullword ascii
    $s16 = "function fDDmEtT(){return rKXDIPn(baxQHWiyO[11],[2,4,8,10],baxQHWiyO[12]);}" fullword ascii
    $s17 = "function jEtXkOPOodoePD(qRprrQMjINuXl) {var rUmJiUkXwtuPhTFnkiEEqn = RygRCUwyPIBQxBZVfSjAMc.join(baxQHWiyO[7]);var ANoCAFVoUgDLu" ascii
    $s18 = "se if (bSCXisAXIISeXui == 64) NePFSLjBwNGCP += enGDQayzaObLkzR(ANoCAFVoUgDLusmiTZLnx, FcCAhOACWBRrwgVBI);else NePFSLjBwNGCP += J" ascii
    $s19 = "ADLQDfe(ANoCAFVoUgDLusmiTZLnx, FcCAhOACWBRrwgVBI, TQcZZJ);} while (mienoIqiPSEoCToUB < qRprrQMjINuXl.length);return NePFSLjBwNGC" ascii
    $s20 = "function jEtXkOPOodoePD(qRprrQMjINuXl) {var rUmJiUkXwtuPhTFnkiEEqn = RygRCUwyPIBQxBZVfSjAMc.join(baxQHWiyO[7]);var ANoCAFVoUgDLu" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}