rule TTP_XOR_QUAD_CurrentVersionRun_7055 {
  strings:
    $key_7055 = { 23 3a [2] 07 34 [2] 2c 18 [2] 02 3a [2] 16 21 [2] 19 3b [2] 07 26 [2] 05 27 [2] 1e 21 [2] 02 26 [2] 1e 09 }

  condition:
    any of them
}