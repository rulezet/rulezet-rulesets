rule _20160921_28d059ae521dbabe2afdc3bfd464938c_20160921_83dee40cf10d_4771 {
  meta:
    description = "datamaliciousorder - from files 20160921_28d059ae521dbabe2afdc3bfd464938c.js, 20160921_83dee40cf10de766ec203f9fab018b5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"
    hash2       = "da20d9f2ad414b6bfc45df4fc34c3fc042e1740d759013b54b408f28740fef3f"

  strings:
    $s1 = "Aa\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function" ascii
    $s2 = "ction f000(){return \"Uo\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s3 = "){return \"TKp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";}" ascii
    $s4 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Mt\";})(),(function f000(){return " ascii
    $s5 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Go\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}