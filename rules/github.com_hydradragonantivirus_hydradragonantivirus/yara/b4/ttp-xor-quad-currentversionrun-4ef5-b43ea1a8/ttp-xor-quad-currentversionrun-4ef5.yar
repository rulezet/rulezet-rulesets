rule TTP_XOR_QUAD_CurrentVersionRun_4ef5 {
  strings:
    $key_4ef5 = { 1d 9a [2] 39 94 [2] 12 b8 [2] 3c 9a [2] 28 81 [2] 27 9b [2] 39 86 [2] 3b 87 [2] 20 81 [2] 3c 86 [2] 20 a9 }

  condition:
    any of them
}