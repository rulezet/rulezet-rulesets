rule TTP_XOR_QUAD_CurrentVersionRun_7077 {
  strings:
    $key_7077 = { 23 18 [2] 07 16 [2] 2c 3a [2] 02 18 [2] 16 03 [2] 19 19 [2] 07 04 [2] 05 05 [2] 1e 03 [2] 02 04 [2] 1e 2b }

  condition:
    any of them
}