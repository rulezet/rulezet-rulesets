rule TTP_XOR_QUAD_CurrentVersionRun_76f4 {
  strings:
    $key_76f4 = { 25 9b [2] 01 95 [2] 2a b9 [2] 04 9b [2] 10 80 [2] 1f 9a [2] 01 87 [2] 03 86 [2] 18 80 [2] 04 87 [2] 18 a8 }

  condition:
    any of them
}