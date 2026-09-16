rule sig_20160313_36d3fd99fd91fbfb88443c3a7a8508da {
  meta:
    description = "datamaliciousorder - file 20160313_36d3fd99fd91fbfb88443c3a7a8508da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cbb528cfb2cb925a4d8496a1715ae8510d9d393ff66afc45ced5bd2ea87ae7f"

  strings:
    $s1  = "return xnEiKMN[0] + xnEiKMN[2] + xnEiKMN[4] + \".F\" + xnEiKMN[7] + xnEiKMN[9] + xnEiKMN[12] + xnEiKMN[14];" fullword ascii
    $s2  = "var Qo = true  , hWRr = Fuk[7] + Fuk[9] + Fuk[11];" fullword ascii
    $s3  = "var xnEiKMN = \"Sc gZzrZmk r QmgFDLPGk ipting bvwdUlx GvU ile umxvWvFtEcQqrj System cJ qzmhu Obj ZWUexH ect IfIyRyv\".split(\" " ascii
    $s4  = "var Fuk = (\"2.XMLHTTP LXmjoSe xQIbM XML ream St ixHmopwl AD HpZwSRf O deqp D\").split(\" \");" fullword ascii
    $s5  = "EHTtQ.open(IuCrV,JSulr,false);" fullword ascii
    $s6  = "function eyRFIlBEZ() {" fullword ascii
    $s7  = "function fZMk(KVqLd) {" fullword ascii
    $s8  = "function kqyhZwd(yvmS,gkSVo) {" fullword ascii
    $s9  = "function EZas(ekOyY) {" fullword ascii
    $s10 = "function exnyx(KAlNqW) {" fullword ascii
    $s11 = "return KAlNqW.position=554-554;" fullword ascii
    $s12 = "return new ActiveXObject(yAEQje);" fullword ascii
    $s13 = "return kqyhZwd(RZ,egXZU[198-192]+egXZU[240-233]+egXZU[186-178]);" fullword ascii
    $s14 = "if (r >= ekOyY.length) {break;}" fullword ascii
    $s15 = "return UBIZJ.status;" fullword ascii
    $s16 = "function glmy(PPoMg) {" fullword ascii
    $s17 = "function Seiw(EHTtQ,JSulr,IuCrV) {" fullword ascii
    $s18 = "function jhUC(XWNwq,FrgMO) {" fullword ascii
    $s19 = "return yvmS.ExpandEnvironmentStrings(gkSVo);" fullword ascii
    $s20 = "return RkCS.responseBody;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}