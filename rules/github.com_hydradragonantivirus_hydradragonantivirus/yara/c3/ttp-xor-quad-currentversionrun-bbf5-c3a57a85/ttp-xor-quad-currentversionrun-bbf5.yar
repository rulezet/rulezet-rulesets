rule TTP_XOR_QUAD_CurrentVersionRun_bbf5 {
  strings:
    $key_bbf5 = { e8 9a [2] cc 94 [2] e7 b8 [2] c9 9a [2] dd 81 [2] d2 9b [2] cc 86 [2] ce 87 [2] d5 81 [2] c9 86 [2] d5 a9 }

  condition:
    any of them
}