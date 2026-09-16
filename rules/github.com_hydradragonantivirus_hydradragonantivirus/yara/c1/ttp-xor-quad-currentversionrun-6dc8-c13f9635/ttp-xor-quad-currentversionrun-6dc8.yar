rule TTP_XOR_QUAD_CurrentVersionRun_6dc8 {
  strings:
    $key_6dc8 = { 3e a7 [2] 1a a9 [2] 31 85 [2] 1f a7 [2] 0b bc [2] 04 a6 [2] 1a bb [2] 18 ba [2] 03 bc [2] 1f bb [2] 03 94 }

  condition:
    any of them
}