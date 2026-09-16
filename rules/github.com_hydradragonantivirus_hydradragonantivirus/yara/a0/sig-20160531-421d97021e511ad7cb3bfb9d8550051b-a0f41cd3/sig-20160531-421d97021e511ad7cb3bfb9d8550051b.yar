rule sig_20160531_421d97021e511ad7cb3bfb9d8550051b {
  meta:
    description = "datamaliciousorder - file 20160531_421d97021e511ad7cb3bfb9d8550051b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2346763b9e3d0832c80cb870e08ba37a5c314ed1937f3f5c3e731cb919bd19cc"

  strings:
    $s1  = "var nyazEhcM=function(){return WScript.CreateObject(aJIsX[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function DpHUSxHh(onPEblh,EHypyeNatEEbnat){return onPEblh.charAt(EHypyeNatEEbnat);}" fullword ascii
    $s3  = " (aEAbKgUlmfOISELMpzlT == 64) degusHKzmTdPDyicWe += iZVvunpNgFvbyrPNztLs(DRIqUIYVCTRNLL, BxjyYH);else degusHKzmTdPDyicWe += ELkL" ascii
    $s4  = "function dZvgiTosHeAvXx(MyYfBkPejHbKZ) {var CvKmqtHdiqEcEPABugMgKocJ = jXseBFqHrIOngciLvyvZkjSM.join(aJIsX[7]);var DRIqUIYVCTRNL" ascii
    $s5  = "WM,true);KhPCkvhOh.WriteLine(kdsAmgu);KhPCkvhOh.Close();}" fullword ascii
    $s6  = "function cfUeORTUZ(){return OfdqwSxChgGv(aJIsX[13],[0,3,6],aJIsX[14]);}" fullword ascii
    $s7  = "function iZVvunpNgFvbyrPNztLs(IXhPRlrlNCeoyEXLbdJCWOn,LgzizAmBAqYRH){return String.fromCharCode(IXhPRlrlNCeoyEXLbdJCWOn,LgzizAmB" ascii
    $s8  = "function FdBtCPBuCQ(akYxXZKxb,aZzwzWomoNGgy) {var wsedQKyWnfU=[aJIsX[15]];akYxXZKxb[wsedQKyWnfU[0]]" fullword ascii
    $s9  = "QXGDKojcPlGV<hlsRolzDifYOfW.length;bCQXGDKojcPlGV++) {KhWnlgyqMb+=JuJNU[hlsRolzDifYOfW[bCQXGDKojcPlGV]];}return KhWnlgyqMb.subst" ascii
    $s10 = "function ELkLCYJVNH(KrqCYjxMyZMaIG,nHfhpTOAAr,BJGHoxDNmEetoNCLpfQKS){return String.fromCharCode(KrqCYjxMyZMaIG,nHfhpTOAAr,BJGHox" ascii
    $s11 = "function OfdqwSxChgGv(tOlZFSKx,hlsRolzDifYOfW,WmECkT){JuJNU=tOlZFSKx.split(WmECkT);KhWnlgyqMb = aJIsX[0];for(bCQXGDKojcPlGV=0;bC" ascii
    $s12 = "push(\"v\");jXseBFqHrIOngciLvyvZkjSM.push(\"w\");jXseBFqHrIOngciLvyvZkjSM.push(\"x\");jXseBFqHrIOngciLvyvZkjSM.push(\"y\");jXseB" ascii
    $s13 = "function ELkLCYJVNH(KrqCYjxMyZMaIG,nHfhpTOAAr,BJGHoxDNmEetoNCLpfQKS){return String.fromCharCode(KrqCYjxMyZMaIG,nHfhpTOAAr,BJGHox" ascii
    $s14 = "function SrvHoDEcMpVH(){return nyazEhcM.ExpandEnvironmentStrings(qZgQMQbdE())}" fullword ascii
    $s15 = "CYJVNH(DRIqUIYVCTRNLL, BxjyYH, yXfeLNAgyYUbec);} while (tWPTrRZgl < MyYfBkPejHbKZ.length);return degusHKzmTdPDyicWe;}" fullword ascii
    $s16 = "function iZVvunpNgFvbyrPNztLs(IXhPRlrlNCeoyEXLbdJCWOn,LgzizAmBAqYRH){return String.fromCharCode(IXhPRlrlNCeoyEXLbdJCWOn,LgzizAmB" ascii
    $s17 = "xff;yXfeLNAgyYUbec = LyQessuryYfZdJrJBy & 0xff;if (qLRdDIFJWCmoXaAeoNHVr == 64) degusHKzmTdPDyicWe += am(DRIqUIYVCTRNLL);else if" ascii
    $s18 = "ring(3,KhWnlgyqMb.length);}" fullword ascii
    $s19 = "(aZzwzWomoNGgy,0x1,0x0)}function BmYFafanKpWJL(zSICkZhOaO,UHmNMUCWkWM,kdsAmgu){var KhPCkvhOh=zSICkZhOaO.createtextfile(UHmNMUCWk" ascii
    $s20 = "function dZvgiTosHeAvXx(MyYfBkPejHbKZ) {var CvKmqtHdiqEcEPABugMgKocJ = jXseBFqHrIOngciLvyvZkjSM.join(aJIsX[7]);var DRIqUIYVCTRNL" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}