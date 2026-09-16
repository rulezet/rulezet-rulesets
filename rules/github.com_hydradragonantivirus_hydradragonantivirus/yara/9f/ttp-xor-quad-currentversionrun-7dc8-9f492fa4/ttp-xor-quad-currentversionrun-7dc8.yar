rule TTP_XOR_QUAD_CurrentVersionRun_7dc8 {
  strings:
    $key_7dc8 = { 2e a7 [2] 0a a9 [2] 21 85 [2] 0f a7 [2] 1b bc [2] 14 a6 [2] 0a bb [2] 08 ba [2] 13 bc [2] 0f bb [2] 13 94 }

  condition:
    any of them
}