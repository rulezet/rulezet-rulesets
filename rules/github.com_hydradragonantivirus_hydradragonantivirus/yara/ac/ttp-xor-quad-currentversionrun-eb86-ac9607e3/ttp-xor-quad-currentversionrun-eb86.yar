rule TTP_XOR_QUAD_CurrentVersionRun_eb86 {
  strings:
    $key_eb86 = { b8 e9 [2] 9c e7 [2] b7 cb [2] 99 e9 [2] 8d f2 [2] 82 e8 [2] 9c f5 [2] 9e f4 [2] 85 f2 [2] 99 f5 [2] 85 da }

  condition:
    any of them
}