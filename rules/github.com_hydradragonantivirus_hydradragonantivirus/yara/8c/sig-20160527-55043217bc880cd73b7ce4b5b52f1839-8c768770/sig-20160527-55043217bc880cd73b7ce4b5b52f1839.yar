rule sig_20160527_55043217bc880cd73b7ce4b5b52f1839 {
  meta:
    description = "datamaliciousorder - file 20160527_55043217bc880cd73b7ce4b5b52f1839.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "305d7acceb15cc574a22a2ca53530c0cd471c7c182eaf0b84b699dd4cc282df4"

  strings:
    $s1  = "function yElbFHGaMfkPn() {return WScript;}function NLFWgZNYoWRFxJ(){return oUoBSbZCHqV.ExpandEnvironmentStrings(NWxPdr())}" fullword ascii
    $s2  = "function IUyyATDOwnXAi(OkxJyOfLIQGKmg,bdpvGfCw){return OkxJyOfLIQGKmg.charAt(bdpvGfCw);}" fullword ascii
    $s3  = "function RodwvYDU(){return OcnSdB(mdJUOqPsn[10],[2,4,8,10],mdJUOqPsn[11]);}" fullword ascii
    $s4  = " 64) fRSCEmNT += RIgYqeXCzino(MxhiiphcdTSXQOG, gGglloYwXh);else fRSCEmNT += OUQYFBPEIw(MxhiiphcdTSXQOG, gGglloYwXh, AZXmRJucEGAx" ascii
    $s5  = "92)+mdJUOqPsn[4],true);" fullword ascii
    $s6  = "function i(LGkCLHZCfbfKgzTLBr){return String.fromCharCode(LGkCLHZCfbfKgzTLBr);}" fullword ascii
    $s7  = "function OcnSdB(cvomvdPfX,ZnyQdGwVriuYDq,eBWDzdpIxiyJP){PgbNTJg=cvomvdPfX.split(eBWDzdpIxiyJP);AkIMYjc = mdJUOqPsn[14];for(cTuAQ" ascii
    $s8  = "var oUoBSbZCHqV=function(){return yElbFHGaMfkPn().CreateObject(mdJUOqPsn[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s9  = "function RIgYqeXCzino(kUIedEizjzhMfyaPZv,JIlrRvpnmYSlLZCUSsxQDfem){return String.fromCharCode(kUIedEizjzhMfyaPZv,JIlrRvpnmYSlLZC" ascii
    $s10 = "kFCN=0;cTuAQkFCN<ZnyQdGwVriuYDq.length;cTuAQkFCN++) {AkIMYjc+=PgbNTJg[ZnyQdGwVriuYDq[cTuAQkFCN]];}return AkIMYjc.substring(3,AkI" ascii
    $s11 = "ZXmRJucEGAxeMH = dROvPoF & 0xff;if (YEzLgDKsMIxUvLRQd == 64) fRSCEmNT += i(MxhiiphcdTSXQOG);else if (RAzMNLKWZsaeeIWNfPbmEObN ==" ascii
    $s12 = "function OUQYFBPEIw(NVEGpQo,WOYMXznk,OWaTAsRe){return String.fromCharCode(NVEGpQo,WOYMXznk,OWaTAsRe);}" fullword ascii
    $s13 = "var pZMhZIyeRm = gZuaAGmygVG.createtextfile(oUoBSbZCHqV.ExpandEnvironmentStrings(mdJUOqPsn[2]+mdJUOqPsn[3])+String.fromCharCode(" ascii
    $s14 = "function NWxPdr(){return OcnSdB(mdJUOqPsn[8],[1,5,7],mdJUOqPsn[9]);}" fullword ascii
    $s15 = "function RIgYqeXCzino(kUIedEizjzhMfyaPZv,JIlrRvpnmYSlLZCUSsxQDfem){return String.fromCharCode(kUIedEizjzhMfyaPZv,JIlrRvpnmYSlLZC" ascii
    $s16 = "eMH);} while (EQoDriYLIWUmmsdLRBX < afpRSPIgDXxzZ.length);return fRSCEmNT;}" fullword ascii
    $s17 = "function XLNGtQs(APXHqcBQgXQqC,RsrVELZLISgDKo) {var oJNavkOCE=[mdJUOqPsn[15]];APXHqcBQgXQqC[oJNavkOCE[0]](RsrVELZLISgDKo,0x1,0x0" ascii
    $s18 = "function KqUZA(){return OcnSdB(mdJUOqPsn[12],[0,3,6],mdJUOqPsn[13]);}" fullword ascii
    $s19 = "var gZuaAGmygVG=function(){return new ActiveXObject(mdJUOqPsn[0]);}();" fullword ascii
    $s20 = "function XLNGtQs(APXHqcBQgXQqC,RsrVELZLISgDKo) {var oJNavkOCE=[mdJUOqPsn[15]];APXHqcBQgXQqC[oJNavkOCE[0]](RsrVELZLISgDKo,0x1,0x0" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}