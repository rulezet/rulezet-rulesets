rule TTP_XOR_QUAD_CurrentVersionRun_5fb5 {
  strings:
    $key_5fb5 = { 0c da [2] 28 d4 [2] 03 f8 [2] 2d da [2] 39 c1 [2] 36 db [2] 28 c6 [2] 2a c7 [2] 31 c1 [2] 2d c6 [2] 31 e9 }

  condition:
    any of them
}