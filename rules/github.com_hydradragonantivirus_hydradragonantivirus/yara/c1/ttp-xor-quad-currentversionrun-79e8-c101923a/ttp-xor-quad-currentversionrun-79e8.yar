rule TTP_XOR_QUAD_CurrentVersionRun_79e8 {
  strings:
    $key_79e8 = { 2a 87 [2] 0e 89 [2] 25 a5 [2] 0b 87 [2] 1f 9c [2] 10 86 [2] 0e 9b [2] 0c 9a [2] 17 9c [2] 0b 9b [2] 17 b4 }

  condition:
    any of them
}