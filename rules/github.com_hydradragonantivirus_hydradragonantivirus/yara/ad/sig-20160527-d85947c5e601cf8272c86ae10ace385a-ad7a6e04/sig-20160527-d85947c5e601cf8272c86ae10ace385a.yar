rule sig_20160527_d85947c5e601cf8272c86ae10ace385a {
  meta:
    description = "datamaliciousorder - file 20160527_d85947c5e601cf8272c86ae10ace385a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f8484185442c7a821f23922354b5881cff0f987f4153714bfc30e63a184a14d"

  strings:
    $s1  = "function HHOaPtV() {return WScript;}function lUssrzsju(){return ErISKihlMrrsoA.ExpandEnvironmentStrings(FCnWalRz())}" fullword ascii
    $s2  = "function vMUKuwMiiL(UTEDyLtlQBVqhTXamWiM,BSmKLWu){return UTEDyLtlQBVqhTXamWiM.charAt(BSmKLWu);}" fullword ascii
    $s3  = "ring(3,oYSPEZtbhO.length);}" fullword ascii
    $s4  = "var sPUFPRGepRMrJ = XbWQiwXW.createtextfile(ErISKihlMrrsoA.ExpandEnvironmentStrings(LtPSmzrhjznf[2]+LtPSmzrhjznf[3])+String.from" ascii
    $s5  = "function SUCwHYGhJPoC(){return vzEZifBjryG(LtPSmzrhjznf[10],[2,4,8,10],LtPSmzrhjznf[11]);}" fullword ascii
    $s6  = "function PvMpkjiYZnVFkGpmNLqkIY(FIMKDs,hEfCJpWGxFUHEJ){return String.fromCharCode(FIMKDs,hEfCJpWGxFUHEJ);}" fullword ascii
    $s7  = "function SKDwtq(WBvaZsSOXiashMxWnpblhdv,JIGMRZaBgsA,tucNyTwiTF){return String.fromCharCode(WBvaZsSOXiashMxWnpblhdv,JIGMRZaBgsA,t" ascii
    $s8  = "function WUuHQumvgQab(fbLdGYdpg,XuHOhqXGZtMiD) {var VvtBqVAKPk=[LtPSmzrhjznf[15]];fbLdGYdpg[VvtBqVAKPk[0]](XuHOhqXGZtMiD,0x1,0x0" ascii
    $s9  = "function WUuHQumvgQab(fbLdGYdpg,XuHOhqXGZtMiD) {var VvtBqVAKPk=[LtPSmzrhjznf[15]];fbLdGYdpg[VvtBqVAKPk[0]](XuHOhqXGZtMiD,0x1,0x0" ascii
    $s10 = "function vzEZifBjryG(VHzihOnyy,nTFipuFqUBT,DTsXFNHE){TBUsiXr=VHzihOnyy.split(DTsXFNHE);oYSPEZtbhO = LtPSmzrhjznf[14];for(XGcJjqu" ascii
    $s11 = "function Dv(qKPQBln){return String.fromCharCode(qKPQBln);}" fullword ascii
    $s12 = "var XbWQiwXW=function(){return new ActiveXObject(LtPSmzrhjznf[0]);}();" fullword ascii
    $s13 = "CharCode(92)+LtPSmzrhjznf[4],true);" fullword ascii
    $s14 = "function vzEZifBjryG(VHzihOnyy,nTFipuFqUBT,DTsXFNHE){TBUsiXr=VHzihOnyy.split(DTsXFNHE);oYSPEZtbhO = LtPSmzrhjznf[14];for(XGcJjqu" ascii
    $s15 = "function rCyThMHvAtrzktPOO(GBGsQuiHjqurPe,qGwwDqtuOYirjrEWtfAWhm){return GBGsQuiHjqurPe.indexOf(qGwwDqtuOYirjrEWtfAWhm);}" fullword ascii
    $s16 = "var ErISKihlMrrsoA=function(){return HHOaPtV().CreateObject(LtPSmzrhjznf[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s17 = "function lKdwdWhUKXLdni(){return vzEZifBjryG(LtPSmzrhjznf[12],[0,3,6],LtPSmzrhjznf[13]);}" fullword ascii
    $s18 = "batGD=0;XGcJjqubatGD<nTFipuFqUBT.length;XGcJjqubatGD++) {oYSPEZtbhO+=TBUsiXr[nTFipuFqUBT[XGcJjqubatGD]];}return oYSPEZtbhO.subst" ascii
    $s19 = "Jh);} while (xeiwJCQbl < nfJiNOyABjYKL.length);return KidRvuKqxi;}" fullword ascii
    $s20 = "function FCnWalRz(){return vzEZifBjryG(LtPSmzrhjznf[8],[1,5,7],LtPSmzrhjznf[9]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}