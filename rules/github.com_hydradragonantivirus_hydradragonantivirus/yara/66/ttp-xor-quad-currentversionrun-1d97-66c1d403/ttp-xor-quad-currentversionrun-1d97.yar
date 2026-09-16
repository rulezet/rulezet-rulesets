rule TTP_XOR_QUAD_CurrentVersionRun_1d97 {
  strings:
    $key_1d97 = { 4e f8 [2] 6a f6 [2] 41 da [2] 6f f8 [2] 7b e3 [2] 74 f9 [2] 6a e4 [2] 68 e5 [2] 73 e3 [2] 6f e4 [2] 73 cb }

  condition:
    any of them
}