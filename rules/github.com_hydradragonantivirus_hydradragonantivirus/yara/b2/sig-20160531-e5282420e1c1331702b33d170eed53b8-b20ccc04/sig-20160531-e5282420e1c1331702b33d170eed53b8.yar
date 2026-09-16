rule sig_20160531_e5282420e1c1331702b33d170eed53b8 {
  meta:
    description = "datamaliciousorder - file 20160531_e5282420e1c1331702b33d170eed53b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "130ba222a0b80b94dd990e2bc2144c462b28991f450e8e8bc2c873af8641e11b"

  strings:
    $s1  = "var FMonmNZA=function(){return WScript.CreateObject(sUaXayS[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function ohbgALiyYuLPuUUuoizh(LtMOIzrZSaluDAWqg,ScWPbjKKAVOUXr){return LtMOIzrZSaluDAWqg.charAt(ScWPbjKKAVOUXr);}" fullword ascii
    $s3  = "function eZOQT(VBsUPXRmwVhHt,svEyE){return String.fromCharCode(VBsUPXRmwVhHt,svEyE);}" fullword ascii
    $s4  = "push(\"t\");VVJQVpAGbZGqwO.push(\"u\");VVJQVpAGbZGqwO.push(\"v\");VVJQVpAGbZGqwO.push(\"w\");VVJQVpAGbZGqwO.push(\"x\");VVJQVpAG" ascii
    $s5  = "FpsQMWq.length;mltogea++) {EDPAnHjTxSwwPv+=OGJNsHcq[FpsQMWq[mltogea]];}return EDPAnHjTxSwwPv.substring(3,EDPAnHjTxSwwPv.length);" ascii
    $s6  = "var KmCxcqHdwdv=function(){return new ActiveXObject(sUaXayS[1]);}();" fullword ascii
    $s7  = "function YLPUHZwezQJaPDUyuY(edJqwkPEsSJJFSnJsvJcl,RSuJQXXPwZGfwVhqq,gKIJVdVl){return String.fromCharCode(edJqwkPEsSJJFSnJsvJcl,R" ascii
    $s8  = "HddGSREiBauhiCSaSZxS);} while (JMEhfafkqzPKiCynxNZwCqY < dGeMsBxjlUzEE.length);return wJHURnriaBgl;}" fullword ascii
    $s9  = "function QjtVdIPWL(TjRAX,tcwDNujNmhlD) {var gJSClRt=[sUaXayS[15]];TjRAX[gJSClRt[0]]" fullword ascii
    $s10 = "wJHURnriaBgl += eZOQT(DMHfXK, ZMMzNBTXYTsMgRTjAzJvLLD);else wJHURnriaBgl += YLPUHZwezQJaPDUyuY(DMHfXK, ZMMzNBTXYTsMgRTjAzJvLLD, " ascii
    $s11 = "iCSaSZxS = MgWZHAvxgSLAzhK & 0xff;if (vylslkcYqbioFBSE == 64) wJHURnriaBgl += j(DMHfXK);else if (lkBLlHYPFpzmVcqbIiAkJHE == 64) " ascii
    $s12 = "function AEpbGHzNHjL(){return VZrPRXECY(sUaXayS[13],[0,3,6],sUaXayS[14]);}" fullword ascii
    $s13 = "(tcwDNujNmhlD,0x1,0x0)}function MklalldlAGWZW(EEkoSkEkM,TMefj,hfrhdRw){var bqRfTTNyhvaMD=EEkoSkEkM.createtextfile(TMefj,true);bq" ascii
    $s14 = "function mrWlKHaboyGfb(zPCucn,ZkWYKofQpKAjgOSljMw){return zPCucn.indexOf(ZkWYKofQpKAjgOSljMw);}" fullword ascii
    $s15 = "function j(PtNgrcFrbBgz){return String.fromCharCode(PtNgrcFrbBgz);}" fullword ascii
    $s16 = "function rWTQynScSQS(){return VZrPRXECY(sUaXayS[9],[1,5,7],sUaXayS[10]);}" fullword ascii
    $s17 = "function YLPUHZwezQJaPDUyuY(edJqwkPEsSJJFSnJsvJcl,RSuJQXXPwZGfwVhqq,gKIJVdVl){return String.fromCharCode(edJqwkPEsSJJFSnJsvJcl,R" ascii
    $s18 = "function VZrPRXECY(MYzRuZT,FpsQMWq,YKpNJWnG){OGJNsHcq=MYzRuZT.split(YKpNJWnG);EDPAnHjTxSwwPv = sUaXayS[0];for(mltogea=0;mltogea<" ascii
    $s19 = "function fUGEsHJ(){return VZrPRXECY(sUaXayS[11],[2,4,8,10],sUaXayS[12]);}" fullword ascii
    $s20 = "function KbgtOFgnUkJC(){return FMonmNZA.ExpandEnvironmentStrings(rWTQynScSQS())}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}