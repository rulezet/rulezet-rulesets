rule TTP_XOR_QUAD_CurrentVersionRun_76e8 {
  strings:
    $key_76e8 = { 25 87 [2] 01 89 [2] 2a a5 [2] 04 87 [2] 10 9c [2] 1f 86 [2] 01 9b [2] 03 9a [2] 18 9c [2] 04 9b [2] 18 b4 }

  condition:
    any of them
}