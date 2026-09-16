rule TTP_XOR_QUAD_CurrentVersionRun_4197 {
  strings:
    $key_4197 = { 12 f8 [2] 36 f6 [2] 1d da [2] 33 f8 [2] 27 e3 [2] 28 f9 [2] 36 e4 [2] 34 e5 [2] 2f e3 [2] 33 e4 [2] 2f cb }

  condition:
    any of them
}