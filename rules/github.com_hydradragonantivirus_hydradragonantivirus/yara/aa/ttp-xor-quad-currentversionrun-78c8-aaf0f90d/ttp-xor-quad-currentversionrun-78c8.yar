rule TTP_XOR_QUAD_CurrentVersionRun_78c8 {
  strings:
    $key_78c8 = { 2b a7 [2] 0f a9 [2] 24 85 [2] 0a a7 [2] 1e bc [2] 11 a6 [2] 0f bb [2] 0d ba [2] 16 bc [2] 0a bb [2] 16 94 }

  condition:
    any of them
}