rule TTP_XOR_QUAD_CurrentVersionRun_4dc8 {
  strings:
    $key_4dc8 = { 1e a7 [2] 3a a9 [2] 11 85 [2] 3f a7 [2] 2b bc [2] 24 a6 [2] 3a bb [2] 38 ba [2] 23 bc [2] 3f bb [2] 23 94 }

  condition:
    any of them
}