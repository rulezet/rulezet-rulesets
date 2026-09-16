rule TTP_XOR_QUAD_CurrentVersionRun_68c8 {
  strings:
    $key_68c8 = { 3b a7 [2] 1f a9 [2] 34 85 [2] 1a a7 [2] 0e bc [2] 01 a6 [2] 1f bb [2] 1d ba [2] 06 bc [2] 1a bb [2] 06 94 }

  condition:
    any of them
}