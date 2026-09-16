rule TTP_XOR_QUAD_CurrentVersionRun_18c8 {
  strings:
    $key_18c8 = { 4b a7 [2] 6f a9 [2] 44 85 [2] 6a a7 [2] 7e bc [2] 71 a6 [2] 6f bb [2] 6d ba [2] 76 bc [2] 6a bb [2] 76 94 }

  condition:
    any of them
}