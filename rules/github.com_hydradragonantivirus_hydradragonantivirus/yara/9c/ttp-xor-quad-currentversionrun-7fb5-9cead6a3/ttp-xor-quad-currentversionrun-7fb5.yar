rule TTP_XOR_QUAD_CurrentVersionRun_7fb5 {
  strings:
    $key_7fb5 = { 2c da [2] 08 d4 [2] 23 f8 [2] 0d da [2] 19 c1 [2] 16 db [2] 08 c6 [2] 0a c7 [2] 11 c1 [2] 0d c6 [2] 11 e9 }

  condition:
    any of them
}