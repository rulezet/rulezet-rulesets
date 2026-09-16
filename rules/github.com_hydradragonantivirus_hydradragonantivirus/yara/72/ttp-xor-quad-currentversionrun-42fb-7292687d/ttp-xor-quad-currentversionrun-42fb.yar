rule TTP_XOR_QUAD_CurrentVersionRun_42fb {
  strings:
    $key_42fb = { 11 94 [2] 35 9a [2] 1e b6 [2] 30 94 [2] 24 8f [2] 2b 95 [2] 35 88 [2] 37 89 [2] 2c 8f [2] 30 88 [2] 2c a7 }

  condition:
    any of them
}