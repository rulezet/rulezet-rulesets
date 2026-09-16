rule _20160921_d47b4a8df4397da0f8d93fe0d9eeb14b_20160922_99c635a67f89_5707 {
  meta:
    description = "datamaliciousorder - from files 20160921_d47b4a8df4397da0f8d93fe0d9eeb14b.js, 20160922_99c635a67f8963210ce99c7a8cf9cd6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78db1c7c22d3adc33c9ba580ac46df953d36c9c15f9c8b211dc68c16595dc18d"
    hash2       = "c5b5cdc3be24f457939814321b7f3397a8f4d2370b1e57cdae1f3f10537e562c"

  strings:
    $s1 = "eturn \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"Qz\";})()," ascii
    $s2 = "eturn \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Qa\";})()" ascii
    $s3 = ")(),(function f000(){return \"Yv\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"XTn\";})(),(function f000(" ascii
    $s4 = "0(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Yz\";}" ascii
    $s5 = "(function f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}