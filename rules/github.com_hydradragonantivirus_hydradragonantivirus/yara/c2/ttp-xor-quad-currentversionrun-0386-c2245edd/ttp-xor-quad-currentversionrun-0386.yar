rule TTP_XOR_QUAD_CurrentVersionRun_0386 {
  strings:
    $key_0386 = { 50 e9 [2] 74 e7 [2] 5f cb [2] 71 e9 [2] 65 f2 [2] 6a e8 [2] 74 f5 [2] 76 f4 [2] 6d f2 [2] 71 f5 [2] 6d da }

  condition:
    any of them
}