rule sig_20160531_ccc7cc447b91ba66653e043d43b5cc70 {
  meta:
    description = "datamaliciousorder - file 20160531_ccc7cc447b91ba66653e043d43b5cc70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88de7a500277a0eb3900ed0d1c69f62739b2f9f975cc0ac3a032e11a62e15448"

  strings:
    $s1  = "var uYXdsiH=function(){return WScript.CreateObject(DDvYNcvFp[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function OlwMJXSXHijoSlXCOJjgPZ(dKLEroSI,UqvtbvDoRlMOdjY){return dKLEroSI.charAt(UqvtbvDoRlMOdjY);}" fullword ascii
    $s3  = "msTIwWDiy.length;RlVxvcG++) {lGAtcGs+=ZbokgOesKwLb[msTIwWDiy[RlVxvcG]];}return lGAtcGs.substring(3,lGAtcGs.length);}" fullword ascii
    $s4  = "function LpdkbUYckHKLElLayTmwfaPJ(ZcCFYrAk,BWerpDCZyWCmuFOw){return String.fromCharCode(ZcCFYrAk,BWerpDCZyWCmuFOw);}" fullword ascii
    $s5  = "function Pl(fxkFTcCI){return String.fromCharCode(fxkFTcCI);}" fullword ascii
    $s6  = "function pzpKGpqEQCBb(PjGbOmZBxPndg) {var wDClCyRaOKqElRFGhi = TskDCPMN.join(DDvYNcvFp[7]);var wiMDKKU, tZKXhXahKkuP, xfCVyakZ, " ascii
    $s7  = "function bRXmGnRaAR(MbTVe,msTIwWDiy,qrolfUXsG){ZbokgOesKwLb=MbTVe.split(qrolfUXsG);lGAtcGs = DDvYNcvFp[0];for(RlVxvcG=0;RlVxvcG<" ascii
    $s8  = "var MaWCNbcMHh=function(){return new ActiveXObject(DDvYNcvFp[1]);}();" fullword ascii
    $s9  = "function bRXmGnRaAR(MbTVe,msTIwWDiy,qrolfUXsG){ZbokgOesKwLb=MbTVe.split(qrolfUXsG);lGAtcGs = DDvYNcvFp[0];for(RlVxvcG=0;RlVxvcG<" ascii
    $s10 = "function aWhXiZU(TbFvE,fhJhCRJxxVTUVxAx,hwEwPyXCXGWSBRU){return String.fromCharCode(TbFvE,fhJhCRJxxVTUVxAx,hwEwPyXCXGWSBRU);}" fullword ascii
    $s11 = "function glOuqhORoVI(){return bRXmGnRaAR(DDvYNcvFp[13],[0,3,6],DDvYNcvFp[14]);}" fullword ascii
    $s12 = "function KTdfZHN(){return bRXmGnRaAR(DDvYNcvFp[11],[2,4,8,10],DDvYNcvFp[12]);}" fullword ascii
    $s13 = "function LkgKeED(bQzVXJZ,ZIlcfEXCBK) {var VwDBHumelMoY=[DDvYNcvFp[15]];bQzVXJZ[VwDBHumelMoY[0]]" fullword ascii
    $s14 = "function wSfXLllRlKyRgBiyX(qNQPYOt,AtgDDsYodSaR){return qNQPYOt.indexOf(AtgDDsYodSaR);}" fullword ascii
    $s15 = "rOeeKuFc += Pl(wiMDKKU);else if (PMJZNkDVxWKzkfKystCmjS == 64) fhmCOrOeeKuFc += LpdkbUYckHKLElLayTmwfaPJ(wiMDKKU, tZKXhXahKkuP);" ascii
    $s16 = "else fhmCOrOeeKuFc += aWhXiZU(wiMDKKU, tZKXhXahKkuP, xfCVyakZ);} while (hdJoDVymqsh < PjGbOmZBxPndg.length);return fhmCOrOeeKuFc" ascii
    $s17 = "(ZIlcfEXCBK,0x1,0x0)}function nlfXWUgS(hcrMSiJl,wyaXsubBu,rtbxQXuOR){var kZiUQfmvD=hcrMSiJl.createtextfile(wyaXsubBu,true);kZiUQ" ascii
    $s18 = "function nJmmZa(){return bRXmGnRaAR(DDvYNcvFp[9],[1,5,7],DDvYNcvFp[10]);}" fullword ascii
    $s19 = "function OWVPzFDQvKgJTM(){return uYXdsiH.ExpandEnvironmentStrings(nJmmZa())}" fullword ascii
    $s20 = "(ZIlcfEXCBK,0x1,0x0)}function nlfXWUgS(hcrMSiJl,wyaXsubBu,rtbxQXuOR){var kZiUQfmvD=hcrMSiJl.createtextfile(wyaXsubBu,true);kZiUQ" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}