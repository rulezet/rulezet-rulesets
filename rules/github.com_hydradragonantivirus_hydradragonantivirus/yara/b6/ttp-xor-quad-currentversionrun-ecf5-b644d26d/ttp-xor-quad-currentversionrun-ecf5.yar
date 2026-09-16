rule TTP_XOR_QUAD_CurrentVersionRun_ecf5 {
  strings:
    $key_ecf5 = { bf 9a [2] 9b 94 [2] b0 b8 [2] 9e 9a [2] 8a 81 [2] 85 9b [2] 9b 86 [2] 99 87 [2] 82 81 [2] 9e 86 [2] 82 a9 }

  condition:
    any of them
}