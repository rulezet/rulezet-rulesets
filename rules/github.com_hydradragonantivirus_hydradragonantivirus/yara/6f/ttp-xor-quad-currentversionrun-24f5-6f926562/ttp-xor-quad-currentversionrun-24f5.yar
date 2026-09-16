rule TTP_XOR_QUAD_CurrentVersionRun_24f5 {
  strings:
    $key_24f5 = { 77 9a [2] 53 94 [2] 78 b8 [2] 56 9a [2] 42 81 [2] 4d 9b [2] 53 86 [2] 51 87 [2] 4a 81 [2] 56 86 [2] 4a a9 }

  condition:
    any of them
}