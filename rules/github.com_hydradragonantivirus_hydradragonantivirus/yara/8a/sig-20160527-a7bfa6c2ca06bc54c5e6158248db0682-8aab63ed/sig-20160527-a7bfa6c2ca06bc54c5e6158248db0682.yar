rule sig_20160527_a7bfa6c2ca06bc54c5e6158248db0682 {
  meta:
    description = "datamaliciousorder - file 20160527_a7bfa6c2ca06bc54c5e6158248db0682.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b149abc8c7f0bb1efcec59b5a62ebbb561233843f8919bf91156f9c5e0f1c783"

  strings:
    $s1  = "function XWCNXdzOAdmHeH() {return WScript;}function gQvYTJld(){return sRJovf.ExpandEnvironmentStrings(PMnpJzdmlCSoUf())}" fullword ascii
    $s2  = "function EspyzPy(IsmbwjwGF,SResgkfvfk){return IsmbwjwGF.charAt(SResgkfvfk);}" fullword ascii
    $s3  = "function FQZORJgOCJXC(WJfJJWOfBWlax) {var BmsvstWrgRgcLWNT = HaXvM.join(dBecIP[6]);var pfVTw, zvrhzx, uynrVUgqebX, EjGZBSOSUtMPp" ascii
    $s4  = "function FQZORJgOCJXC(WJfJJWOfBWlax) {var BmsvstWrgRgcLWNT = HaXvM.join(dBecIP[6]);var pfVTw, zvrhzx, uynrVUgqebX, EjGZBSOSUtMPp" ascii
    $s5  = "var ZZhYKImmAnqh=function(){return new ActiveXObject(dBecIP[0]);}();" fullword ascii
    $s6  = "var BDCvElDn = ZZhYKImmAnqh.createtextfile(sRJovf.ExpandEnvironmentStrings(dBecIP[2]+dBecIP[3])+String.fromCharCode(92)+dBecIP[4" ascii
    $s7  = "function DgStJio(){return rVhKZFLYTAWAPU(dBecIP[10],[2,4,8,10],dBecIP[11]);}" fullword ascii
    $s8  = "function QypQf(mvBmuuBYovGmod,dMUQbFP) {var PLZjYbQYT=[dBecIP[15]];mvBmuuBYovGmod[PLZjYbQYT[0]](dMUQbFP,0x1,0x0)}" fullword ascii
    $s9  = "function rVhKZFLYTAWAPU(bIKKGjsdTKXUVD,VWzGYLnxESfz,GpAik){oLkmcPQSJ=bIKKGjsdTKXUVD.split(GpAik);SLcOSTxicbJ = dBecIP[14];for(FI" ascii
    $s10 = "function PMnpJzdmlCSoUf(){return rVhKZFLYTAWAPU(dBecIP[8],[1,5,7],dBecIP[9]);}" fullword ascii
    $s11 = "function fYAOcrSvRTavVt(){return rVhKZFLYTAWAPU(dBecIP[12],[0,3,6],dBecIP[13]);}" fullword ascii
    $s12 = "var sRJovf=function(){return XWCNXdzOAdmHeH().CreateObject(dBecIP[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s13 = ", uynrVUgqebX);} while (CJJEtTTTjAWjNqkrdzFVjjt < WJfJJWOfBWlax.length);return grAMt;}" fullword ascii
    $s14 = "function nIzLVXKTAzFY(kWEYYivuY,efltyMVSDWRr){return String.fromCharCode(kWEYYivuY,efltyMVSDWRr);}" fullword ascii
    $s15 = "function rVhKZFLYTAWAPU(bIKKGjsdTKXUVD,VWzGYLnxESfz,GpAik){oLkmcPQSJ=bIKKGjsdTKXUVD.split(GpAik);SLcOSTxicbJ = dBecIP[14];for(FI" ascii
    $s16 = "oLUnGYmzS=0;FIoLUnGYmzS<VWzGYLnxESfz.length;FIoLUnGYmzS++) {SLcOSTxicbJ+=oLkmcPQSJ[VWzGYLnxESfz[FIoLUnGYmzS]];}return SLcOSTxicb" ascii
    $s17 = "function pJhbi(zhsGwELk,xQxacrOLrEwZf){return zhsGwELk.indexOf(xQxacrOLrEwZf);}" fullword ascii
    $s18 = "function jd(kvIsPXFMYG){return String.fromCharCode(kvIsPXFMYG);}" fullword ascii
    $s19 = "],true);" fullword ascii
    $s20 = "function neduGrAMFKROzGcAnkgXT(VeuuoMbzxL,vfOzDJjgcchvxtpr,GNsRi){return String.fromCharCode(VeuuoMbzxL,vfOzDJjgcchvxtpr,GNsRi);" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}