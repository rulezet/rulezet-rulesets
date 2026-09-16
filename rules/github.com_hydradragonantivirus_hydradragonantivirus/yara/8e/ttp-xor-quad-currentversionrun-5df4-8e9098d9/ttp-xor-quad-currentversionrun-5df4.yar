rule TTP_XOR_QUAD_CurrentVersionRun_5df4 {
  strings:
    $key_5df4 = { 0e 9b [2] 2a 95 [2] 01 b9 [2] 2f 9b [2] 3b 80 [2] 34 9a [2] 2a 87 [2] 28 86 [2] 33 80 [2] 2f 87 [2] 33 a8 }

  condition:
    any of them
}