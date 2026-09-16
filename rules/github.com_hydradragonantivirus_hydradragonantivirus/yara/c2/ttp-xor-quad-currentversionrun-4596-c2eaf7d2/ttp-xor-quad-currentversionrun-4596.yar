rule TTP_XOR_QUAD_CurrentVersionRun_4596 {
  strings:
    $key_4596 = { 16 f9 [2] 32 f7 [2] 19 db [2] 37 f9 [2] 23 e2 [2] 2c f8 [2] 32 e5 [2] 30 e4 [2] 2b e2 [2] 37 e5 [2] 2b ca }

  condition:
    any of them
}