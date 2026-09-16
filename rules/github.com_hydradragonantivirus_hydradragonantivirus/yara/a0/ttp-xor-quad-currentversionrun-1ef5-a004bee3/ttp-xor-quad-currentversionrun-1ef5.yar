rule TTP_XOR_QUAD_CurrentVersionRun_1ef5 {
  strings:
    $key_1ef5 = { 4d 9a [2] 69 94 [2] 42 b8 [2] 6c 9a [2] 78 81 [2] 77 9b [2] 69 86 [2] 6b 87 [2] 70 81 [2] 6c 86 [2] 70 a9 }

  condition:
    any of them
}