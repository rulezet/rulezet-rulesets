rule TTP_XOR_QUAD_CurrentVersionRun_0ef5 {
  strings:
    $key_0ef5 = { 5d 9a [2] 79 94 [2] 52 b8 [2] 7c 9a [2] 68 81 [2] 67 9b [2] 79 86 [2] 7b 87 [2] 60 81 [2] 7c 86 [2] 60 a9 }

  condition:
    any of them
}