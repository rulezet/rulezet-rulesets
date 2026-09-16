rule TTP_XOR_QUAD_CurrentVersionRun_4d97 {
  strings:
    $key_4d97 = { 1e f8 [2] 3a f6 [2] 11 da [2] 3f f8 [2] 2b e3 [2] 24 f9 [2] 3a e4 [2] 38 e5 [2] 23 e3 [2] 3f e4 [2] 23 cb }

  condition:
    any of them
}