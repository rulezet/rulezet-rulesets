rule TTP_XOR_QUAD_CurrentVersionRun_6fb5 {
  strings:
    $key_6fb5 = { 3c da [2] 18 d4 [2] 33 f8 [2] 1d da [2] 09 c1 [2] 06 db [2] 18 c6 [2] 1a c7 [2] 01 c1 [2] 1d c6 [2] 01 e9 }

  condition:
    any of them
}