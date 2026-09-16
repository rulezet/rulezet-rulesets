rule TTP_XOR_QUAD_CurrentVersionRun_4296 {
  strings:
    $key_4296 = { 11 f9 [2] 35 f7 [2] 1e db [2] 30 f9 [2] 24 e2 [2] 2b f8 [2] 35 e5 [2] 37 e4 [2] 2c e2 [2] 30 e5 [2] 2c ca }

  condition:
    any of them
}