rule _20160921_5eea6af1c50b807f547cb710eb413110_20160921_b32c8921e339_5274 {
  meta:
    description = "datamaliciousorder - from files 20160921_5eea6af1c50b807f547cb710eb413110.js, 20160921_b32c8921e3390cb8f9450436f4e43cfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0791148d3e03ce3d231765cb1183a7c90ac5567405736f3d6780502908893b46"
    hash2       = "5ab35ff2eba15a460823fc709e29f7c1041f054096a3690e92c926943d39d6a8"

  strings:
    $s1 = "k\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(functio" ascii
    $s2 = "0(){return \"Qz\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";}" ascii
    $s3 = "tion f000(){return \"ZIi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"XTn\";})(),(function f000(){retur" ascii
    $s4 = "0(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NBs\";" ascii
    $s5 = "){return \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}