rule TTP_XOR_QUAD_CurrentVersionRun_5e96 {
  strings:
    $key_5e96 = { 0d f9 [2] 29 f7 [2] 02 db [2] 2c f9 [2] 38 e2 [2] 37 f8 [2] 29 e5 [2] 2b e4 [2] 30 e2 [2] 2c e5 [2] 30 ca }

  condition:
    any of them
}