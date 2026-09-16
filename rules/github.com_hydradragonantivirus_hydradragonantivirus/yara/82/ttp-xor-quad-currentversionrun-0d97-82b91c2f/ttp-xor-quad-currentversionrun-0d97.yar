rule TTP_XOR_QUAD_CurrentVersionRun_0d97 {
  strings:
    $key_0d97 = { 5e f8 [2] 7a f6 [2] 51 da [2] 7f f8 [2] 6b e3 [2] 64 f9 [2] 7a e4 [2] 78 e5 [2] 63 e3 [2] 7f e4 [2] 63 cb }

  condition:
    any of them
}