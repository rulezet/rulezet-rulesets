rule TTP_XOR_QUAD_CurrentVersionRun_0e86 {
  strings:
    $key_0e86 = { 5d e9 [2] 79 e7 [2] 52 cb [2] 7c e9 [2] 68 f2 [2] 67 e8 [2] 79 f5 [2] 7b f4 [2] 60 f2 [2] 7c f5 [2] 60 da }

  condition:
    any of them
}