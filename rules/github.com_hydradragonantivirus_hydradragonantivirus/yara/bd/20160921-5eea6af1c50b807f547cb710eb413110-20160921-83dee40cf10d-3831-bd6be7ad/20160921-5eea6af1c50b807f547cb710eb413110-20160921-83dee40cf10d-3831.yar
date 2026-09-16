rule _20160921_5eea6af1c50b807f547cb710eb413110_20160921_83dee40cf10d_3831 {
  meta:
    description = "datamaliciousorder - from files 20160921_5eea6af1c50b807f547cb710eb413110.js, 20160921_83dee40cf10de766ec203f9fab018b5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0791148d3e03ce3d231765cb1183a7c90ac5567405736f3d6780502908893b46"
    hash2       = "da20d9f2ad414b6bfc45df4fc34c3fc042e1740d759013b54b408f28740fef3f"

  strings:
    $s1 = "){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Wb\";})" ascii
    $s2 = "000(){return \"Br\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"TKp\"" ascii
    $s3 = "unction f000(){return \"Yv\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s4 = "0(){return \"Go\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";" ascii
    $s5 = "\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"XTn\";})(),(function f" ascii
    $s6 = "UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}