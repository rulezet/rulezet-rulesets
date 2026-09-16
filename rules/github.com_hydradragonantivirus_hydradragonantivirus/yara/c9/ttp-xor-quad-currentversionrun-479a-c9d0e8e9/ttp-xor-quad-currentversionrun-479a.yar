rule TTP_XOR_QUAD_CurrentVersionRun_479a {
  strings:
    $key_479a = { 14 f5 [2] 30 fb [2] 1b d7 [2] 35 f5 [2] 21 ee [2] 2e f4 [2] 30 e9 [2] 32 e8 [2] 29 ee [2] 35 e9 [2] 29 c6 }

  condition:
    any of them
}