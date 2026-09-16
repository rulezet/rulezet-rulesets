rule sig_20160530_168936f0c58b05afcb8faa292faf9a3c {
  meta:
    description = "datamaliciousorder - file 20160530_168936f0c58b05afcb8faa292faf9a3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c4b25d2a8be39d3f769fc28a010da64dc543aebdb656655f5a312c7f2993d1f"

  strings:
    $s1  = "var KDNdPRzJyEKhL=function(){return WScript.CreateObject(oeosgEYppTUPRB[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function jTMYUbn(bkmndYjsexueMKSMybe,cGPWBzJfTnVv){return bkmndYjsexueMKSMybe.charAt(cGPWBzJfTnVv);}" fullword ascii
    $s3  = "GLqfonMqkqUzS.length);return SBqxUeEgLdElPbQvewl;}" fullword ascii
    $s4  = "function RjgfHIPKMIaxQ(GLqfonMqkqUzS) {var UADggIgZOTyKJep = DKNEqxk.join(oeosgEYppTUPRB[7]);var AdxafHPJSRMtooLomMxEi, iHkoCksG" ascii
    $s5  = "function xSMwoaNhU(){return KDNdPRzJyEKhL.ExpandEnvironmentStrings(PNTmVzLbCCwqM())}" fullword ascii
    $s6  = " += F(AdxafHPJSRMtooLomMxEi);else if (hKTqtXQGLf == 64) SBqxUeEgLdElPbQvewl += ljAxbcfjakwwuYkuRLqKC(AdxafHPJSRMtooLomMxEi, iHko" ascii
    $s7  = "function VidkvyRelYTOafQAmST(YjaLgAg,pmIbZmllRJEP){return YjaLgAg.indexOf(pmIbZmllRJEP);}" fullword ascii
    $s8  = "function dHBPQkWUZXREd(xLqtBnQk,UlSqVpSEzkrPNh,upOqyIDzZkznX){return String.fromCharCode(xLqtBnQk,UlSqVpSEzkrPNh,upOqyIDzZkznX);" ascii
    $s9  = "function RjgfHIPKMIaxQ(GLqfonMqkqUzS) {var UADggIgZOTyKJep = DKNEqxk.join(oeosgEYppTUPRB[7]);var AdxafHPJSRMtooLomMxEi, iHkoCksG" ascii
    $s10 = "function dHBPQkWUZXREd(xLqtBnQk,UlSqVpSEzkrPNh,upOqyIDzZkznX){return String.fromCharCode(xLqtBnQk,UlSqVpSEzkrPNh,upOqyIDzZkznX);" ascii
    $s11 = "function wlTzV(BUAMnwWyvpHGFQ,qNfYYjvJDxESzP,UQhJvDa){XbfURQx=BUAMnwWyvpHGFQ.split(UQhJvDa);gDQROZGhzEw = oeosgEYppTUPRB[0];for(" ascii
    $s12 = "var nBIZaIijiYJeyS=function(){return new ActiveXObject(oeosgEYppTUPRB[1]);}();" fullword ascii
    $s13 = "function ljAxbcfjakwwuYkuRLqKC(nQNPdCKMHbDYwQfJVDLR,qVlDEVBurDMvXmBVWrEK){return String.fromCharCode(nQNPdCKMHbDYwQfJVDLR,qVlDEV" ascii
    $s14 = "function vAgvSf(){return wlTzV(oeosgEYppTUPRB[13],[0,3,6],oeosgEYppTUPRB[14]);}" fullword ascii
    $s15 = "CksGTneX);else SBqxUeEgLdElPbQvewl += dHBPQkWUZXREd(AdxafHPJSRMtooLomMxEi, iHkoCksGTneX, lOtGqRIE);} while (tkanUqOrFNhCHxYNL < " ascii
    $s16 = "function IJwabdPY(){return wlTzV(oeosgEYppTUPRB[11],[2,4,8,10],oeosgEYppTUPRB[12]);}" fullword ascii
    $s17 = "function PNTmVzLbCCwqM(){return wlTzV(oeosgEYppTUPRB[9],[1,5,7],oeosgEYppTUPRB[10]);}" fullword ascii
    $s18 = "function ljAxbcfjakwwuYkuRLqKC(nQNPdCKMHbDYwQfJVDLR,qVlDEVBurDMvXmBVWrEK){return String.fromCharCode(nQNPdCKMHbDYwQfJVDLR,qVlDEV" ascii
    $s19 = "function vvhqTXLl(TSkeKAQd,fOEERtRk) {var LYRqWd=[oeosgEYppTUPRB[15]];TSkeKAQd[LYRqWd[0]]" fullword ascii
    $s20 = "mCharCode(92)+oeosgEYppTUPRB[5],true);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}