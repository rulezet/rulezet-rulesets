rule TTP_XOR_QUAD_CurrentVersionRun_38f5 {
  strings:
    $key_38f5 = { 6b 9a [2] 4f 94 [2] 64 b8 [2] 4a 9a [2] 5e 81 [2] 51 9b [2] 4f 86 [2] 4d 87 [2] 56 81 [2] 4a 86 [2] 56 a9 }

  condition:
    any of them
}