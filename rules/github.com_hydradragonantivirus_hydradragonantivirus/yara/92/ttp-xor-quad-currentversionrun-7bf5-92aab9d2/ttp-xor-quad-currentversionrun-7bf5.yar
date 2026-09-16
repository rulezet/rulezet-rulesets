rule TTP_XOR_QUAD_CurrentVersionRun_7bf5 {
  strings:
    $key_7bf5 = { 28 9a [2] 0c 94 [2] 27 b8 [2] 09 9a [2] 1d 81 [2] 12 9b [2] 0c 86 [2] 0e 87 [2] 15 81 [2] 09 86 [2] 15 a9 }

  condition:
    any of them
}