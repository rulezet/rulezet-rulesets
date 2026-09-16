rule sig_20160527_711a7d44926f12bf698d94f72e9314e1 {
  meta:
    description = "datamaliciousorder - file 20160527_711a7d44926f12bf698d94f72e9314e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2d3f0250c9c977e86b119d23fcf65a3af2a549f4b849290dd7b8f16c1ca20d3"

  strings:
    $s1  = "function ToNUVul() {return WScript;}function RrNaOypawmjxx(){return vRMAndeSPJ.ExpandEnvironmentStrings(tBndltHpwy())}" fullword ascii
    $s2  = "function NcRQSOm(pBvhYTPXYrBuMWNQljQxTFTX,VLGHKlgFZAYKqLwNWrF){return pBvhYTPXYrBuMWNQljQxTFTX.charAt(VLGHKlgFZAYKqLwNWrF);}" fullword ascii
    $s3  = "function NUbsXHA(mtKrpYESURAPI) {var gFLnEbYlK = fkZIQPNAx.join(GEXkApbQgdsRQXQGPNhnPabY[6]);var QzsfJulrHDSMmJlmcntK, tCQeY, kT" ascii
    $s4  = "function RAqTVtSpi(mncLGObdOsQP,EuHqEr) {var GuZzOZ=[GEXkApbQgdsRQXQGPNhnPabY[15]];mncLGObdOsQP[GuZzOZ[0]](EuHqEr,0x1,0x0)}" fullword ascii
    $s5  = "DPR=0;UfYgMqTGDPR<kjeeDce.length;UfYgMqTGDPR++) {ROlzoUVqSFu+=ZtMRrd[kjeeDce[UfYgMqTGDPR]];}return ROlzoUVqSFu.substring(3,ROlzo" ascii
    $s6  = "function GdqzJ(RFaLfyJSeGLBTdblijItGQQK,hwSPBD,KLkuDwlkHiqfQsqgVzDp){return String.fromCharCode(RFaLfyJSeGLBTdblijItGQQK,hwSPBD," ascii
    $s7  = "< mtKrpYESURAPI.length);return xdcCh;}" fullword ascii
    $s8  = "function GdqzJ(RFaLfyJSeGLBTdblijItGQQK,hwSPBD,KLkuDwlkHiqfQsqgVzDp){return String.fromCharCode(RFaLfyJSeGLBTdblijItGQQK,hwSPBD," ascii
    $s9  = "function wnZJJAwLDCnN(Lusdw,kjeeDce,ofvtdtB){ZtMRrd=Lusdw.split(ofvtdtB);ROlzoUVqSFu = GEXkApbQgdsRQXQGPNhnPabY[14];for(UfYgMqTG" ascii
    $s10 = "var vRMAndeSPJ=function(){return ToNUVul().CreateObject(GEXkApbQgdsRQXQGPNhnPabY[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s11 = "function ppwZAioCIwikvgQZVRJxlMq(CxtZIVSALnAbqTmuN,OZZyYRxzq){return CxtZIVSALnAbqTmuN.indexOf(OZZyYRxzq);}" fullword ascii
    $s12 = "var pHdbyc=function(){return new ActiveXObject(GEXkApbQgdsRQXQGPNhnPabY[0]);}();" fullword ascii
    $s13 = "function wnZJJAwLDCnN(Lusdw,kjeeDce,ofvtdtB){ZtMRrd=Lusdw.split(ofvtdtB);ROlzoUVqSFu = GEXkApbQgdsRQXQGPNhnPabY[14];for(UfYgMqTG" ascii
    $s14 = "function yvYVxZVVlfAUKxvTufzQA(BTNZEXOR,boFNnfiHYaYrXigmamQDQB){return String.fromCharCode(BTNZEXOR,boFNnfiHYaYrXigmamQDQB);}" fullword ascii
    $s15 = "QzsfJulrHDSMmJlmcntK, tCQeY);else xdcCh += GdqzJ(QzsfJulrHDSMmJlmcntK, tCQeY, kTYVapGIVRRdfNQFstjq);} while (xBBZBCHUvgnMOeCPzO " ascii
    $s16 = "function NUbsXHA(mtKrpYESURAPI) {var gFLnEbYlK = fkZIQPNAx.join(GEXkApbQgdsRQXQGPNhnPabY[6]);var QzsfJulrHDSMmJlmcntK, tCQeY, kT" ascii
    $s17 = "function tBndltHpwy(){return wnZJJAwLDCnN(GEXkApbQgdsRQXQGPNhnPabY[8],[1,5,7],GEXkApbQgdsRQXQGPNhnPabY[9]);}" fullword ascii
    $s18 = "function JmBSZwIIU(){return wnZJJAwLDCnN(GEXkApbQgdsRQXQGPNhnPabY[10],[2,4,8,10],GEXkApbQgdsRQXQGPNhnPabY[11]);}" fullword ascii
    $s19 = "function hFJIKH(){return wnZJJAwLDCnN(GEXkApbQgdsRQXQGPNhnPabY[12],[0,3,6],GEXkApbQgdsRQXQGPNhnPabY[13]);}" fullword ascii
    $s20 = "[3])+String.fromCharCode(92)+GEXkApbQgdsRQXQGPNhnPabY[4],true);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}