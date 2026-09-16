rule TTP_XOR_QUAD_CurrentVersionRun_4291 {
  strings:
    $key_4291 = { 11 fe [2] 35 f0 [2] 1e dc [2] 30 fe [2] 24 e5 [2] 2b ff [2] 35 e2 [2] 37 e3 [2] 2c e5 [2] 30 e2 [2] 2c cd }

  condition:
    any of them
}