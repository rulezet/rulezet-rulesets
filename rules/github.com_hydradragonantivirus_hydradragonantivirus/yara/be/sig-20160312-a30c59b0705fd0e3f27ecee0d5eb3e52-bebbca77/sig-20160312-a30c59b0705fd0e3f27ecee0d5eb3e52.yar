rule sig_20160312_a30c59b0705fd0e3f27ecee0d5eb3e52 {
  meta:
    description = "datamaliciousorder - file 20160312_a30c59b0705fd0e3f27ecee0d5eb3e52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "628606862aba43f05d1be59eec9ae9244d4f107def27c0c3eb5b3ece6712e1ce"

  strings:
    $s1  = "var zl = true  , Qcly = yHO[7] + yHO[9] + yHO[11];" fullword ascii
    $s2  = "return HffyuIS[0] + HffyuIS[2] + HffyuIS[4] + \".F\" + HffyuIS[7] + HffyuIS[9] + HffyuIS[12] + HffyuIS[14];" fullword ascii
    $s3  = "var yHO = (\"2.XMLHTTP xvzWuMN TzgtN XML ream St bQAnNYdG AD MoPiQEF O DbPe D\").split(\" \");" fullword ascii
    $s4  = "var HffyuIS = \"Sc hsNzcCF r iKMhxYLqs ipting ijKnYTb QDE ile BWeNWILmMYXWYm System PW lvOTu Obj LEfOXU ect qPSwshl\".split(\" " ascii
    $s5  = "dDEvJ.open(HpyZd,JCqAb,false);" fullword ascii
    $s6  = "return new ActiveXObject(aaSdhx);" fullword ascii
    $s7  = "return BrywY.status;" fullword ascii
    $s8  = "function KRoiWBcRT() {" fullword ascii
    $s9  = "return pBCOOEm(Pl,QVUWa[428-422]+QVUWa[858-851]+QVUWa[588-580]);" fullword ascii
    $s10 = "function hEvx(tdnCM,JASIW) {" fullword ascii
    $s11 = "function aiPB(aVKOT) {" fullword ascii
    $s12 = "function kODh(DAafH) {" fullword ascii
    $s13 = "if (g >= ZNYef.length) {break;}" fullword ascii
    $s14 = "function hrmEfunl() {" fullword ascii
    $s15 = "function lGpbTbRTV(rOXzxWNXtSD) {" fullword ascii
    $s16 = "function lQkw(BrywY) {" fullword ascii
    $s17 = "return jgE.size;" fullword ascii
    $s18 = "function VoKuy(aaSdhx) {" fullword ascii
    $s19 = "function XxpT(dDEvJ,JCqAb,HpyZd) {" fullword ascii
    $s20 = "function ovcl(zFdHD) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}