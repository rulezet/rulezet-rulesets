rule TTP_XOR_QUAD_CurrentVersionRun_03b5 {
  strings:
    $key_03b5 = { 50 da [2] 74 d4 [2] 5f f8 [2] 71 da [2] 65 c1 [2] 6a db [2] 74 c6 [2] 76 c7 [2] 6d c1 [2] 71 c6 [2] 6d e9 }

  condition:
    any of them
}