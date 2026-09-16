rule TTP_XOR_QUAD_CurrentVersionRun_e186 {
  strings:
    $key_e186 = { b2 e9 [2] 96 e7 [2] bd cb [2] 93 e9 [2] 87 f2 [2] 88 e8 [2] 96 f5 [2] 94 f4 [2] 8f f2 [2] 93 f5 [2] 8f da }

  condition:
    any of them
}