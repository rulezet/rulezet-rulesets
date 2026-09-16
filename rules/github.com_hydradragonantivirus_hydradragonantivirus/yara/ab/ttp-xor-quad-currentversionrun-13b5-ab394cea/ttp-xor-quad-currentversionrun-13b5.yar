rule TTP_XOR_QUAD_CurrentVersionRun_13b5 {
  strings:
    $key_13b5 = { 40 da [2] 64 d4 [2] 4f f8 [2] 61 da [2] 75 c1 [2] 7a db [2] 64 c6 [2] 66 c7 [2] 7d c1 [2] 61 c6 [2] 7d e9 }

  condition:
    any of them
}