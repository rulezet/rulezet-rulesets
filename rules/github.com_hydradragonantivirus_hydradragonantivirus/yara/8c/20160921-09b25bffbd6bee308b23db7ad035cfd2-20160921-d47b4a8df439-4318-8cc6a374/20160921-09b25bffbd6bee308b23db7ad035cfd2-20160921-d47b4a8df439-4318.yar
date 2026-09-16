rule _20160921_09b25bffbd6bee308b23db7ad035cfd2_20160921_d47b4a8df439_4318 {
  meta:
    description = "datamaliciousorder - from files 20160921_09b25bffbd6bee308b23db7ad035cfd2.js, 20160921_d47b4a8df4397da0f8d93fe0d9eeb14b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0646df8d41668a96251f0443ca802dda915eadd4bc1fdb29b89948f4eb238893"
    hash2       = "78db1c7c22d3adc33c9ba580ac46df953d36c9c15f9c8b211dc68c16595dc18d"

  strings:
    $s1 = "o\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function" ascii
    $s2 = "000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"YTp" ascii
    $s3 = "rn \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s4 = "nction f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){ret" ascii
    $s5 = "{return \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}