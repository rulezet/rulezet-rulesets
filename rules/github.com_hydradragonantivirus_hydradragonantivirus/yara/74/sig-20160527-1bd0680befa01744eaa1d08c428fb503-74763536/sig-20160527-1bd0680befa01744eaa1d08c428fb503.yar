rule sig_20160527_1bd0680befa01744eaa1d08c428fb503 {
  meta:
    description = "datamaliciousorder - file 20160527_1bd0680befa01744eaa1d08c428fb503.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c808fdfa089450f71f5ea6c2c26a4262724fd8c1dd9f53fbfbf36b7c2fc398e"

  strings:
    $s1  = "function hQTZc() {return WScript;}function OBmCQX(){return fkcdH.ExpandEnvironmentStrings(xCzZeskkGltLih())}" fullword ascii
    $s2  = "function paEtkCQtsPTfAeLr(XwtauATuogwyMOF,XRMmxbwAIfCdtfImHPda){return XwtauATuogwyMOF.charAt(XRMmxbwAIfCdtfImHPda);}" fullword ascii
    $s3  = "oaugnx += oKebiKTtJ(fcZNcPUsYKzJ, kipwUoWhbKwXWuSNhbUIP, ZBuBwTSmTelpSdcZsZbdftz);} while (WBPKBhEipnYyqIwyu < SyvGlXnWdYTma.len" ascii
    $s4  = "var JccNzle = HXNMHeGJoxEv.createtextfile(fkcdH.ExpandEnvironmentStrings(qXRcmgKIHqHgm[2]+qXRcmgKIHqHgm[3])+String.fromCharCode(" ascii
    $s5  = "function DTiXVzo(yHkSmph,fSqSRezMhvbCq) {var TCbyYu=[qXRcmgKIHqHgm[15]];yHkSmph[TCbyYu[0]](fSqSRezMhvbCq,0x1,0x0)}" fullword ascii
    $s6  = "var HXNMHeGJoxEv=function(){return new ActiveXObject(qXRcmgKIHqHgm[0]);}();" fullword ascii
    $s7  = "92)+qXRcmgKIHqHgm[4],true);" fullword ascii
    $s8  = "function MOiqLanCsN(){return SkgjxuvZf(qXRcmgKIHqHgm[10],[2,4,8,10],qXRcmgKIHqHgm[11]);}" fullword ascii
    $s9  = "function DosCbfEHAyRyfBjIhx(KoVaPZgKg,gXertlOyRFdWbxsejx){return KoVaPZgKg.indexOf(gXertlOyRFdWbxsejx);}" fullword ascii
    $s10 = "function zaBJcS(SyvGlXnWdYTma) {var ElSGnjJYLFZVNc = FjqGabqLEcHLOFwMSZiFwx.join(qXRcmgKIHqHgm[6]);var fcZNcPUsYKzJ, kipwUoWhbKw" ascii
    $s11 = "function oKebiKTtJ(IQWNOsXXpXzJTSUvSVPm,MmwXIUQA,bFBJjlNSoDEuHcUMJbpcp){return String.fromCharCode(IQWNOsXXpXzJTSUvSVPm,MmwXIUQA" ascii
    $s12 = "function oKebiKTtJ(IQWNOsXXpXzJTSUvSVPm,MmwXIUQA,bFBJjlNSoDEuHcUMJbpcp){return String.fromCharCode(IQWNOsXXpXzJTSUvSVPm,MmwXIUQA" ascii
    $s13 = "function SkgjxuvZf(VRxREI,VLUIxMAshXinq,nJfQPZSXEFeai){kGxeKhmh=VRxREI.split(nJfQPZSXEFeai);egxLQMQTBUI = qXRcmgKIHqHgm[14];for(" ascii
    $s14 = "function SkgjxuvZf(VRxREI,VLUIxMAshXinq,nJfQPZSXEFeai){kGxeKhmh=VRxREI.split(nJfQPZSXEFeai);egxLQMQTBUI = qXRcmgKIHqHgm[14];for(" ascii
    $s15 = "function xCzZeskkGltLih(){return SkgjxuvZf(qXRcmgKIHqHgm[8],[1,5,7],qXRcmgKIHqHgm[9]);}" fullword ascii
    $s16 = "function pAeJACwhSWa(VjGKrxagZujYT,vdounCmRWeJdZmLtrAMlJgK){return String.fromCharCode(VjGKrxagZujYT,vdounCmRWeJdZmLtrAMlJgK);}" fullword ascii
    $s17 = "function R(bnYcnzwxpfToVNSyz){return String.fromCharCode(bnYcnzwxpfToVNSyz);}" fullword ascii
    $s18 = "gth);return oaugnx;}" fullword ascii
    $s19 = "var fkcdH=function(){return hQTZc().CreateObject(qXRcmgKIHqHgm[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s20 = "ilkzJV == 64) oaugnx += R(fcZNcPUsYKzJ);else if (ikLOWLL == 64) oaugnx += pAeJACwhSWa(fcZNcPUsYKzJ, kipwUoWhbKwXWuSNhbUIP);else " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}