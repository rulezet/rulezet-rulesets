rule TTP_XOR_QUAD_CurrentVersionRun_79f4 {
  strings:
    $key_79f4 = { 2a 9b [2] 0e 95 [2] 25 b9 [2] 0b 9b [2] 1f 80 [2] 10 9a [2] 0e 87 [2] 0c 86 [2] 17 80 [2] 0b 87 [2] 17 a8 }

  condition:
    any of them
}