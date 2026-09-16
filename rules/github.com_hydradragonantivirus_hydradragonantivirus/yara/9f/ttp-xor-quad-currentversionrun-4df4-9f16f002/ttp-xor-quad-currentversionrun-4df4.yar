rule TTP_XOR_QUAD_CurrentVersionRun_4df4 {
  strings:
    $key_4df4 = { 1e 9b [2] 3a 95 [2] 11 b9 [2] 3f 9b [2] 2b 80 [2] 24 9a [2] 3a 87 [2] 38 86 [2] 23 80 [2] 3f 87 [2] 23 a8 }

  condition:
    any of them
}