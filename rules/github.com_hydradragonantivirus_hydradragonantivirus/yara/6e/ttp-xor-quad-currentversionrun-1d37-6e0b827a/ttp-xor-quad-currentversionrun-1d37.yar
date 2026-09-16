rule TTP_XOR_QUAD_CurrentVersionRun_1d37 {
  strings:
    $key_1d37 = { 4e 58 [2] 6a 56 [2] 41 7a [2] 6f 58 [2] 7b 43 [2] 74 59 [2] 6a 44 [2] 68 45 [2] 73 43 [2] 6f 44 [2] 73 6b }

  condition:
    any of them
}