rule sig_20160527_eb86fa6ecc0d4dbc1650469b08a58487 {
  meta:
    description = "datamaliciousorder - file 20160527_eb86fa6ecc0d4dbc1650469b08a58487.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "306b8c3e9cef6f609103425297265cf65b84aa0d958036315fb7e10fd74e7fbd"

  strings:
    $s1  = "function wOoOku() {return WScript;}function GwZWVdufwjHhDW(){return LPEPki.ExpandEnvironmentStrings(nmfGAjKlYBdKa())}" fullword ascii
    $s2  = "function gmYoU(oJJYZmntD,uLzKEvmbskBEPNJure){return oJJYZmntD.charAt(uLzKEvmbskBEPNJure);}" fullword ascii
    $s3  = "function krVcowsROM(XzBUFyKZ,DIimOQYRaO) {var vSJWNqyfncYGRP=[eoCIHkqWoVKsVQc[15]];XzBUFyKZ[vSJWNqyfncYGRP[0]](DIimOQYRaO,0x1,0x" ascii
    $s4  = "function lzNjbZrgwVIcGJ(fInXVzAsekvWWPxgczpc,uZgDoEQFxOty,QVTLBzVlCgPxusqtfl){return String.fromCharCode(fInXVzAsekvWWPxgczpc,uZ" ascii
    $s5  = "function krVcowsROM(XzBUFyKZ,DIimOQYRaO) {var vSJWNqyfncYGRP=[eoCIHkqWoVKsVQc[15]];XzBUFyKZ[vSJWNqyfncYGRP[0]](DIimOQYRaO,0x1,0x" ascii
    $s6  = "function BDLTDpM(){return JHbDYUiuNLFT(eoCIHkqWoVKsVQc[12],[0,3,6],eoCIHkqWoVKsVQc[13]);}" fullword ascii
    $s7  = "var LPEPki=function(){return wOoOku().CreateObject(eoCIHkqWoVKsVQc[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s8  = "function eHeWl(BdSadqnJ,GmdXLzAcUi){return String.fromCharCode(BdSadqnJ,GmdXLzAcUi);}" fullword ascii
    $s9  = "function ImzWwzfV(BARueYupIF,crVqXhOdkJFnu){return BARueYupIF.indexOf(crVqXhOdkJFnu);}" fullword ascii
    $s10 = "function PcXKufMzwoA(dvWsWwiVgmule) {var uoYHogKkiNgUJhEh = UeIyKQEBXvluIAu.join(eoCIHkqWoVKsVQc[6]);var RKdsAkmm, nHwTSkMbekOjy" ascii
    $s11 = "function nmfGAjKlYBdKa(){return JHbDYUiuNLFT(eoCIHkqWoVKsVQc[8],[1,5,7],eoCIHkqWoVKsVQc[9]);}" fullword ascii
    $s12 = ";}return YQOQTAQqbTySM.substring(3,YQOQTAQqbTySM.length);}" fullword ascii
    $s13 = "function lzNjbZrgwVIcGJ(fInXVzAsekvWWPxgczpc,uZgDoEQFxOty,QVTLBzVlCgPxusqtfl){return String.fromCharCode(fInXVzAsekvWWPxgczpc,uZ" ascii
    $s14 = "function JHbDYUiuNLFT(laulEcsvRShq,bmiHSsfMYoQZlV,aMquE){qvhjDrZzmn=laulEcsvRShq.split(aMquE);YQOQTAQqbTySM = eoCIHkqWoVKsVQc[14" ascii
    $s15 = "var oyheSiNHM = UBjcxSOdz.createtextfile(LPEPki.ExpandEnvironmentStrings(eoCIHkqWoVKsVQc[2]+eoCIHkqWoVKsVQc[3])+String.fromCharC" ascii
    $s16 = "function JHbDYUiuNLFT(laulEcsvRShq,bmiHSsfMYoQZlV,aMquE){qvhjDrZzmn=laulEcsvRShq.split(aMquE);YQOQTAQqbTySM = eoCIHkqWoVKsVQc[14" ascii
    $s17 = "hHucVTTMfpcB & 0xff;if (VDOVKhNjEuHLUCcUzItDnrWU == 64) JKRLtqehgvNrFPQTBY += Px(RKdsAkmm);else if (zOQWRLqPSEVPlIYwSJbYG == 64)" ascii
    $s18 = "var UBjcxSOdz=function(){return new ActiveXObject(eoCIHkqWoVKsVQc[0]);}();" fullword ascii
    $s19 = "NaXBeaIThumJdHj);} while (AWYUhA < dvWsWwiVgmule.length);return JKRLtqehgvNrFPQTBY;}" fullword ascii
    $s20 = "function PcXKufMzwoA(dvWsWwiVgmule) {var uoYHogKkiNgUJhEh = UeIyKQEBXvluIAu.join(eoCIHkqWoVKsVQc[6]);var RKdsAkmm, nHwTSkMbekOjy" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}