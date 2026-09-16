rule TTP_XOR_QUAD_CurrentVersionRun_1997 {
  strings:
    $key_1997 = { 4a f8 [2] 6e f6 [2] 45 da [2] 6b f8 [2] 7f e3 [2] 70 f9 [2] 6e e4 [2] 6c e5 [2] 77 e3 [2] 6b e4 [2] 77 cb }

  condition:
    any of them
}