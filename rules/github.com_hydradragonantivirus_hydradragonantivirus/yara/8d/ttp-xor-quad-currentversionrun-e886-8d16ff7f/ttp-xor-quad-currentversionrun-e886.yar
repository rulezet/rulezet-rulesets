rule TTP_XOR_QUAD_CurrentVersionRun_e886 {
  strings:
    $key_e886 = { bb e9 [2] 9f e7 [2] b4 cb [2] 9a e9 [2] 8e f2 [2] 81 e8 [2] 9f f5 [2] 9d f4 [2] 86 f2 [2] 9a f5 [2] 86 da }

  condition:
    any of them
}