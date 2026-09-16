rule TTP_XOR_QUAD_CurrentVersionRun_5996 {
  strings:
    $key_5996 = { 0a f9 [2] 2e f7 [2] 05 db [2] 2b f9 [2] 3f e2 [2] 30 f8 [2] 2e e5 [2] 2c e4 [2] 37 e2 [2] 2b e5 [2] 37 ca }

  condition:
    any of them
}