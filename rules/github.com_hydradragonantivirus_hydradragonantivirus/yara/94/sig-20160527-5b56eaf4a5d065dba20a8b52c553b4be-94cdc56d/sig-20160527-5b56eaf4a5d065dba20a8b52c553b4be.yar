rule sig_20160527_5b56eaf4a5d065dba20a8b52c553b4be {
  meta:
    description = "datamaliciousorder - file 20160527_5b56eaf4a5d065dba20a8b52c553b4be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "047269ce1a4cefb84676329fcf400d83f546ccbb2029e2505a8fcaf0c598291d"

  strings:
    $s1  = "function bHXxWZu() {return WScript;}function tOzsP(){return tDSMhEPNdvvv.ExpandEnvironmentStrings(KzoCsJp())}" fullword ascii
    $s2  = "function qLVPzHe(fBhFJFsKTOphOuFILEfgn,AgLev){return fBhFJFsKTOphOuFILEfgn.charAt(AgLev);}" fullword ascii
    $s3  = "function ZSYgfMomR(kmHHIbiuftilI) {var FYswnCFGaMzwrMaIBpfXllV = pkUVMjkCg.join(sWVsoHDfQnR[6]);var lUEnjeSgf, YnDgW, ZGFyVIdznO" ascii
    $s4  = "var tDSMhEPNdvvv=function(){return bHXxWZu().CreateObject(sWVsoHDfQnR[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s5  = "var wVrYlroOomrY = qNiaDz.createtextfile(tDSMhEPNdvvv.ExpandEnvironmentStrings(sWVsoHDfQnR[2]+sWVsoHDfQnR[3])+String.fromCharCod" ascii
    $s6  = ");return KMHoarGYvwYZ;}" fullword ascii
    $s7  = "function eNeYwod(ppFNVksyw,rFGmkiD,oyxWZsvgXkggI){vxWqgZngGU=ppFNVksyw.split(oyxWZsvgXkggI);grnlQE = sWVsoHDfQnR[14];for(bVvcTFi" ascii
    $s8  = "e(92)+sWVsoHDfQnR[4],true);" fullword ascii
    $s9  = "function ZlzQbSvINtLqIZdFJteBAAEh(toOrEfRBiYXcipmENu,amtqpuimDjBXGzUKJj){return String.fromCharCode(toOrEfRBiYXcipmENu,amtqpuimD" ascii
    $s10 = "function tqtuuLqwF(){return eNeYwod(sWVsoHDfQnR[10],[2,4,8,10],sWVsoHDfQnR[11]);}" fullword ascii
    $s11 = "var qNiaDz=function(){return new ActiveXObject(sWVsoHDfQnR[0]);}();" fullword ascii
    $s12 = "function viLrGFljUdnDPseyManAdjXM(OTsbwWfDLZelQlXYHeDf,VhTxfXkkwv){return OTsbwWfDLZelQlXYHeDf.indexOf(VhTxfXkkwv);}" fullword ascii
    $s13 = "function rHPeIbOwvRLlLITrOnsgenNt(obkuRkJBlo,BSrQlNyRqF,LeoFfkhxZBhOKbYI){return String.fromCharCode(obkuRkJBlo,BSrQlNyRqF,LeoFf" ascii
    $s14 = "function rHPeIbOwvRLlLITrOnsgenNt(obkuRkJBlo,BSrQlNyRqF,LeoFfkhxZBhOKbYI){return String.fromCharCode(obkuRkJBlo,BSrQlNyRqF,LeoFf" ascii
    $s15 = "function wzYEiRRLD(rAadnrzNoQMBcF,CHnloeKiv) {var lTJWvMVkSdJV=[sWVsoHDfQnR[15]];rAadnrzNoQMBcF[lTJWvMVkSdJV[0]](CHnloeKiv,0x1,0" ascii
    $s16 = "function ZSYgfMomR(kmHHIbiuftilI) {var FYswnCFGaMzwrMaIBpfXllV = pkUVMjkCg.join(sWVsoHDfQnR[6]);var lUEnjeSgf, YnDgW, ZGFyVIdznO" ascii
    $s17 = "DgW);else KMHoarGYvwYZ += rHPeIbOwvRLlLITrOnsgenNt(lUEnjeSgf, YnDgW, ZGFyVIdznOJJSbE);} while (MCejEMzuFH < kmHHIbiuftilI.length" ascii
    $s18 = "function wzYEiRRLD(rAadnrzNoQMBcF,CHnloeKiv) {var lTJWvMVkSdJV=[sWVsoHDfQnR[15]];rAadnrzNoQMBcF[lTJWvMVkSdJV[0]](CHnloeKiv,0x1,0" ascii
    $s19 = "FNFzToRBE == 64) KMHoarGYvwYZ += QQ(lUEnjeSgf);else if (EMRMBHobNS == 64) KMHoarGYvwYZ += ZlzQbSvINtLqIZdFJteBAAEh(lUEnjeSgf, Yn" ascii
    $s20 = "ddTljk=0;bVvcTFiddTljk<rFGmkiD.length;bVvcTFiddTljk++) {grnlQE+=vxWqgZngGU[rFGmkiD[bVvcTFiddTljk]];}return grnlQE.substring(3,gr" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}