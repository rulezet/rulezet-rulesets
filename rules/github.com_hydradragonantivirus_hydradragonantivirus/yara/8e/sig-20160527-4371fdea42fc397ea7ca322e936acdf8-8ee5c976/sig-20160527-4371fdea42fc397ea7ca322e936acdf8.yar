rule sig_20160527_4371fdea42fc397ea7ca322e936acdf8 {
  meta:
    description = "datamaliciousorder - file 20160527_4371fdea42fc397ea7ca322e936acdf8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e37c299c8c25d357e20bff75ef4c0647e09ca090a9cf9040625a6ac9ed719944"

  strings:
    $s1  = "function RDdkxdJV() {return WScript;}function oKWxtrfHW(){return PakqPCtHHDbnS.ExpandEnvironmentStrings(SksxBikwiI())}" fullword ascii
    $s2  = "function MmKVWIPxUfPyGOuzor(ZIMsRUAOoCcXcclCrDeE,xuRNM){return ZIMsRUAOoCcXcclCrDeE.charAt(xuRNM);}" fullword ascii
    $s3  = "push(\"t\");VwqYEyXmIsKGuE.push(\"u\");VwqYEyXmIsKGuE.push(\"v\");VwqYEyXmIsKGuE.push(\"w\");VwqYEyXmIsKGuE.push(\"x\");VwqYEyXm" ascii
    $s4  = "function ApJZzdAKP(ouJpIZHwsUwmdJ,TVbwNnVEtkmHBGApWLEo){return String.fromCharCode(ouJpIZHwsUwmdJ,TVbwNnVEtkmHBGApWLEo);}" fullword ascii
    $s5  = "function FZUqzZvhy(){return UKkJJJJWY(cilQC[10],[2,4,8,10],cilQC[11]);}" fullword ascii
    $s6  = "function UKkJJJJWY(dULTPSbxdaRPk,NAcZpV,mFuUh){YlWXstjJr=dULTPSbxdaRPk.split(mFuUh);TInDGOKoF = cilQC[14];for(ydmgCnkFTI=0;ydmgC" ascii
    $s7  = "var PakqPCtHHDbnS=function(){return RDdkxdJV().CreateObject(cilQC[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s8  = "function YhKXX(ZdIpPQiihzPsJJEHIPK,aLJxAmPWhj,zrLGZCqzFRZBwjQzPftuBZ){return String.fromCharCode(ZdIpPQiihzPsJJEHIPK,aLJxAmPWhj," ascii
    $s9  = "nkFTI<NAcZpV.length;ydmgCnkFTI++) {TInDGOKoF+=YlWXstjJr[NAcZpV[ydmgCnkFTI]];}return TInDGOKoF.substring(3,TInDGOKoF.length);}" fullword ascii
    $s10 = "var LQDwM=function(){return new ActiveXObject(cilQC[0]);}();" fullword ascii
    $s11 = "function SksxBikwiI(){return UKkJJJJWY(cilQC[8],[1,5,7],cilQC[9]);}" fullword ascii
    $s12 = "function oDobkgxdUKn(){return UKkJJJJWY(cilQC[12],[0,3,6],cilQC[13]);}" fullword ascii
    $s13 = "var RJTZSrTgTaWa = LQDwM.createtextfile(PakqPCtHHDbnS.ExpandEnvironmentStrings(cilQC[2]+cilQC[3])+String.fromCharCode(92)+cilQC[" ascii
    $s14 = "gSMGxX, LCvhgJtUIxeVBpf);} while (DXuoXkk < hjSZRfXCotwlU.length);return IFScxexBQGe;}" fullword ascii
    $s15 = "function rrUaTOkTYGP(hjSZRfXCotwlU) {var NWOaEMnySfQRvFNc = VwqYEyXmIsKGuE.join(cilQC[6]);var AuRzKQnYRE, yOzgSMGxX, LCvhgJtUIxe" ascii
    $s16 = "function SUPXmfcbgAenQyAwFWE(shVavhHBVed,ldaWGgKXXWvGcdOHf){return shVavhHBVed.indexOf(ldaWGgKXXWvGcdOHf);}" fullword ascii
    $s17 = "function YhKXX(ZdIpPQiihzPsJJEHIPK,aLJxAmPWhj,zrLGZCqzFRZBwjQzPftuBZ){return String.fromCharCode(ZdIpPQiihzPsJJEHIPK,aLJxAmPWhj," ascii
    $s18 = "function ze(vpcvbRmowa){return String.fromCharCode(vpcvbRmowa);}" fullword ascii
    $s19 = "function ofsKZAV(pKCgwDJlH,UTOvepua) {var zWDZMo=[cilQC[15]];pKCgwDJlH[zWDZMo[0]](UTOvepua,0x1,0x0)}" fullword ascii
    $s20 = "function UKkJJJJWY(dULTPSbxdaRPk,NAcZpV,mFuUh){YlWXstjJr=dULTPSbxdaRPk.split(mFuUh);TInDGOKoF = cilQC[14];for(ydmgCnkFTI=0;ydmgC" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}