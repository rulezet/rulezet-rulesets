rule TTP_XOR_QUAD_CurrentVersionRun_7df4 {
  strings:
    $key_7df4 = { 2e 9b [2] 0a 95 [2] 21 b9 [2] 0f 9b [2] 1b 80 [2] 14 9a [2] 0a 87 [2] 08 86 [2] 13 80 [2] 0f 87 [2] 13 a8 }

  condition:
    any of them
}