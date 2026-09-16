rule sig_20160527_9a252e1ad6af245fcbdae318f1e2359c {
  meta:
    description = "datamaliciousorder - file 20160527_9a252e1ad6af245fcbdae318f1e2359c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbda1cf14e344214243b79b69650d6b0deb6789db7303f8b20634820bcc18048"

  strings:
    $s1  = "function lYWFcG() {return WScript;}function ueIGJCLRP(){return eijNxkL.ExpandEnvironmentStrings(JmFthx())}" fullword ascii
    $s2  = "function ukmGL(cNZUQxlwAVNc,GKnXcTLO){return cNZUQxlwAVNc.charAt(GKnXcTLO);}" fullword ascii
    $s3  = "ing.fromCharCode(92)+rZtqpjEKXNISzHrZCrzAH[4],true);" fullword ascii
    $s4  = "ZCrzAH[14];for(qKvHhbTCIM=0;qKvHhbTCIM<eReNan.length;qKvHhbTCIM++) {BHKwcVjmQh+=NhAeOdZmAcEWv[eReNan[qKvHhbTCIM]];}return BHKwcV" ascii
    $s5  = "function BOYXhLTTnKJZYhLxG(lsxnNWtdaCXnhw,JLKCEjLzEkzyRvQxAZUlRJ){return lsxnNWtdaCXnhw.indexOf(JLKCEjLzEkzyRvQxAZUlRJ);}" fullword ascii
    $s6  = "xkToaPuUwp < YEgYJgmoWGJVr.length);return zdCEderIMAXBaekBQgqDRfmL;}" fullword ascii
    $s7  = "function aEyPR(YEgYJgmoWGJVr) {var NkquvsrJ = vlJTSTKTVinXGsrWdu.join(rZtqpjEKXNISzHrZCrzAH[6]);var gEFYcvgDuNFCOYgadfNGRrI, INp" ascii
    $s8  = "var NpekvFL = WqInuuoSvlx.createtextfile(eijNxkL.ExpandEnvironmentStrings(rZtqpjEKXNISzHrZCrzAH[2]+rZtqpjEKXNISzHrZCrzAH[3])+Str" ascii
    $s9  = "function QOoTDZAKQgPIu(){return QpuwSwJkMtKlS(rZtqpjEKXNISzHrZCrzAH[10],[2,4,8,10],rZtqpjEKXNISzHrZCrzAH[11]);}" fullword ascii
    $s10 = "function NvhCypJmDdCTm(){return QpuwSwJkMtKlS(rZtqpjEKXNISzHrZCrzAH[12],[0,3,6],rZtqpjEKXNISzHrZCrzAH[13]);}" fullword ascii
    $s11 = "BaekBQgqDRfmL += zs(gEFYcvgDuNFCOYgadfNGRrI);else if (WxiXJET == 64) zdCEderIMAXBaekBQgqDRfmL += aYoKMhz(gEFYcvgDuNFCOYgadfNGRrI" ascii
    $s12 = "var WqInuuoSvlx=function(){return new ActiveXObject(rZtqpjEKXNISzHrZCrzAH[0]);}();" fullword ascii
    $s13 = "function aYoKMhz(oARuOvldKyAPcolTfK,TdsNYZLmWthmiu){return String.fromCharCode(oARuOvldKyAPcolTfK,TdsNYZLmWthmiu);}" fullword ascii
    $s14 = "function JmFthx(){return QpuwSwJkMtKlS(rZtqpjEKXNISzHrZCrzAH[8],[1,5,7],rZtqpjEKXNISzHrZCrzAH[9]);}" fullword ascii
    $s15 = "push(\"D\");vlJTSTKTVinXGsrWdu.push(\"3\");vlJTSTKTVinXGsrWdu.push(\"E\");vlJTSTKTVinXGsrWdu.push(\"F\");vlJTSTKTVinXGsrWdu.push" ascii
    $s16 = "function aEyPR(YEgYJgmoWGJVr) {var NkquvsrJ = vlJTSTKTVinXGsrWdu.join(rZtqpjEKXNISzHrZCrzAH[6]);var gEFYcvgDuNFCOYgadfNGRrI, INp" ascii
    $s17 = "function QpuwSwJkMtKlS(LDbCbPhAJ,eReNan,UWjjSnYXPiltB){NhAeOdZmAcEWv=LDbCbPhAJ.split(UWjjSnYXPiltB);BHKwcVjmQh = rZtqpjEKXNISzHr" ascii
    $s18 = "function zs(VsEVTwSHPgQppRSVdDi){return String.fromCharCode(VsEVTwSHPgQppRSVdDi);}" fullword ascii
    $s19 = ", INpnISLyhj);else zdCEderIMAXBaekBQgqDRfmL += gztVjddRGQQSbXKYo(gEFYcvgDuNFCOYgadfNGRrI, INpnISLyhj, oNLaegdbCwIz);} while (yXe" ascii
    $s20 = "function QpuwSwJkMtKlS(LDbCbPhAJ,eReNan,UWjjSnYXPiltB){NhAeOdZmAcEWv=LDbCbPhAJ.split(UWjjSnYXPiltB);BHKwcVjmQh = rZtqpjEKXNISzHr" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}