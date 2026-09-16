rule TTP_XOR_QUAD_CurrentVersionRun_5eb5 {
  strings:
    $key_5eb5 = { 0d da [2] 29 d4 [2] 02 f8 [2] 2c da [2] 38 c1 [2] 37 db [2] 29 c6 [2] 2b c7 [2] 30 c1 [2] 2c c6 [2] 30 e9 }

  condition:
    any of them
}