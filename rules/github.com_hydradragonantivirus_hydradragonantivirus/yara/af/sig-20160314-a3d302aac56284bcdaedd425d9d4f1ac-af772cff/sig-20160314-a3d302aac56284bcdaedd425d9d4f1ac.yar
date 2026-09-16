rule sig_20160314_a3d302aac56284bcdaedd425d9d4f1ac {
  meta:
    description = "datamaliciousorder - file 20160314_a3d302aac56284bcdaedd425d9d4f1ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f0c1139c0b2fe64a217072dc494efbc91df22f63330c34d2109aff6d4bae87e"

  strings:
    $s1  = "var Cm = true  , qWas = Upg[7] + Upg[9] + Upg[11];" fullword ascii
    $s2  = "return EsYXseu[0] + EsYXseu[2] + EsYXseu[4] + \".F\" + EsYXseu[7] + EsYXseu[9] + EsYXseu[12] + EsYXseu[14];" fullword ascii
    $s3  = "var EsYXseu = \"Sc AubVMYk r aBctjAeBH ipting MyLyTVj ilv ile oddOApGtZJBnvJ System Yz eMtzh Obj zVxjiB ect JQZQGfa DQxvm\".spli" ascii
    $s4  = "DTglU.open(mtnbg,YnKnc,false);" fullword ascii
    $s5  = "return qqCMd.status;" fullword ascii
    $s6  = "function YvxH(qqCMd) {" fullword ascii
    $s7  = "var EsYXseu = \"Sc AubVMYk r aBctjAeBH ipting MyLyTVj ilv ile oddOApGtZJBnvJ System Yz eMtzh Obj zVxjiB ect JQZQGfa DQxvm\".spli" ascii
    $s8  = "var Upg = (\"2.XMLHTTP wslGSTh ziinm XML ream St jlDJUUIN AD CxXntUi O jlPC D\").split(\" \");" fullword ascii
    $s9  = "if(h>=s.length) {break;}" fullword ascii
    $s10 = "if (Xximx == 920-720){return true;} else {return false;}" fullword ascii
    $s11 = "function NkuvMyh(ldHO) {" fullword ascii
    $s12 = "NUU = h; break; " fullword ascii
    $s13 = "return iHjcteh(MH,uoXtN[360-354]+uoXtN[807-800]+uoXtN[682-674]);" fullword ascii
    $s14 = "function oNoCQ(RDEqbR) {" fullword ascii
    $s15 = "function rGsU(Xximx) {" fullword ascii
    $s16 = "function dvoa(uiIxr) {" fullword ascii
    $s17 = "function uUKY(IUGHY,FRbqK) {" fullword ascii
    $s18 = "function GAwqe(ZRtyxy) {" fullword ascii
    $s19 = "if (uiIxr > 166945-861){return true;} else {return false;}" fullword ascii
    $s20 = "function WNwY(TEZnS) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}