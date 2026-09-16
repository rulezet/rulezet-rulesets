rule TTP_XOR_QUAD_CurrentVersionRun_76e9 {
  strings:
    $key_76e9 = { 25 86 [2] 01 88 [2] 2a a4 [2] 04 86 [2] 10 9d [2] 1f 87 [2] 01 9a [2] 03 9b [2] 18 9d [2] 04 9a [2] 18 b5 }

  condition:
    any of them
}