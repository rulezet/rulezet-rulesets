rule sig_20160308_0c5eadbf3b42af898e1c5f0248fa849a {
  meta:
    description = "datamaliciousorder - file 20160308_0c5eadbf3b42af898e1c5f0248fa849a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58cfdaa205518430bb066fa8eeb232d080605185b2b68d8c637b239353e06e3b"

  strings:
    $s1  = "function oAzK(ILogy,NpYYM) {" fullword ascii
    $s2  = "var Dx = true  , pPkJ = CFr[7] + CFr[9] + CFr[11];" fullword ascii
    $s3  = "return OsorhZp[0] + OsorhZp[2] + OsorhZp[4] + \".F\" + OsorhZp[7] + OsorhZp[9] + OsorhZp[12] + OsorhZp[14];" fullword ascii
    $s4  = "var OsorhZp = \"Sc LtTMhXI r jczJfAkqZ ipting wztCdzx CCz ile hGLFyKZxRDxHPH System nm MZhLc Obj SsRSRV ect LHVbJco\".split(\" " ascii
    $s5  = "skSaT.open(tdQGb,LfOiy,false);" fullword ascii
    $s6  = "var CFr = (\"2.XMLHTTP iPxmOgt NQUdn XML ream St qsMkQUNI AD seVormv O FkqH D\").split(\" \");" fullword ascii
    $s7  = "return sG.ExpandEnvironmentStrings(iSpbF[6]+iSpbF[7]+iSpbF[8]);" fullword ascii
    $s8  = "function hCmo(NlTwQ) {" fullword ascii
    $s9  = "return xNhZa;" fullword ascii
    $s10 = "if(a>=y.length) {break;}" fullword ascii
    $s11 = "if (L >= LXtPJ.length) {break;}" fullword ascii
    $s12 = "function FzjMEMdMr(vhhJC,SpdLG,qyHRR,iAhM) {" fullword ascii
    $s13 = "Cme = a; break; " fullword ascii
    $s14 = "function XFoi(WyhoW) {" fullword ascii
    $s15 = "return xrA.size;" fullword ascii
    $s16 = "function wjUlcWG(SJJG) {" fullword ascii
    $s17 = "if (WyhoW > 150849-401){return true;} else {return false;}" fullword ascii
    $s18 = "function HCoH(LXtPJ) {" fullword ascii
    $s19 = "if (IoIXM == 831-631){return true;} else {return false;}" fullword ascii
    $s20 = "function BftFhwNU(xrA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}