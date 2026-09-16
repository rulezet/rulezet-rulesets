rule TTP_XOR_QUAD_CurrentVersionRun_ecf4 {
  strings:
    $key_ecf4 = { bf 9b [2] 9b 95 [2] b0 b9 [2] 9e 9b [2] 8a 80 [2] 85 9a [2] 9b 87 [2] 99 86 [2] 82 80 [2] 9e 87 [2] 82 a8 }

  condition:
    any of them
}