rule sig_20160526_96c8b1bbc63c12dac3aeaa68e6233d34 {
  meta:
    description = "datamaliciousorder - file 20160526_96c8b1bbc63c12dac3aeaa68e6233d34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7204b4615b92c6d78e1bfa55712495fbf0b451ebe3f27a4a0da2108cef840c93"

  strings:
    $s1  = "Math.sin(823), 2) + Math.pow(Math.cos(823), 2) - 1))-604)) RALWUtosHjuKwpiY += UO(JMcszSqXcVfETunXNlp);else if (zqWxHPtXwqr == (" ascii
    $s2  = "function HBDQZgepmEIfu(cLDndizBNqNBc) {var aJJhTKRFOC = xwGWYqRpLgkbTfjcyXy.join(oFmpZOvUdkbscObK[0]);var JMcszSqXcVfETunXNlp, f" ascii
    $s3  = "n(504), 2) + Math.pow(Math.cos(504), 2) - 1))-221) | vzGhGCzXAGcrerIsSpm<< (425 + Math.round((Math.pow(Math.sin(804), 2) + Math." ascii
    $s4  = "function odGPVIUAz(sczLrpYPOmbqHeNh,YSOACtzsige){return sczLrpYPOmbqHeNh.charAt(YSOACtzsige);}" fullword ascii
    $s5  = "function HBDQZgepmEIfu(cLDndizBNqNBc) {var aJJhTKRFOC = xwGWYqRpLgkbTfjcyXy.join(oFmpZOvUdkbscObK[0]);var JMcszSqXcVfETunXNlp, f" ascii
    $s6  = "function JHNbxf(gjMTkTcFONJWYhC,LikwkSYBTW){return String.fromCharCode(gjMTkTcFONJWYhC,LikwkSYBTW);}" fullword ascii
    $s7  = "function UO(TDdUpdYZMwEBLsmBLF){return String.fromCharCode(TDdUpdYZMwEBLsmBLF);}" fullword ascii
    $s8  = "function VOwfohTsFwadDEGW(gXqWNkuWadRM,hIgDiiviTFCpSAohsodi,JwkSPf){return String.fromCharCode(gXqWNkuWadRM,hIgDiiviTFCpSAohsodi" ascii
    $s9  = "function VOwfohTsFwadDEGW(gXqWNkuWadRM,hIgDiiviTFCpSAohsodi,JwkSPf){return String.fromCharCode(gXqWNkuWadRM,hIgDiiviTFCpSAohsodi" ascii
    $s10 = "XNlp, fWaPbHTWUl);else RALWUtosHjuKwpiY += VOwfohTsFwadDEGW(JMcszSqXcVfETunXNlp, fWaPbHTWUl, uibNhuBLOYxADhrssnYhsZwh);} while (" ascii
    $s11 = "function gpaxQstRvq(lbWNmdhCIrvOnbRHCWvFsIVg,OcrCygSp){return lbWNmdhCIrvOnbRHCWvFsIVg.indexOf(OcrCygSp);}" fullword ascii
    $s12 = "ZnktldVNaqCPcfLDTVwow < cLDndizBNqNBc.length);return RALWUtosHjuKwpiY;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}