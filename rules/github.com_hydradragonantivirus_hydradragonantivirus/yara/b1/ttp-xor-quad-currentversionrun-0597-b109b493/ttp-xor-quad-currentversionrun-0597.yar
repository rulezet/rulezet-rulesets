rule TTP_XOR_QUAD_CurrentVersionRun_0597 {
  strings:
    $key_0597 = { 56 f8 [2] 72 f6 [2] 59 da [2] 77 f8 [2] 63 e3 [2] 6c f9 [2] 72 e4 [2] 70 e5 [2] 6b e3 [2] 77 e4 [2] 6b cb }

  condition:
    any of them
}