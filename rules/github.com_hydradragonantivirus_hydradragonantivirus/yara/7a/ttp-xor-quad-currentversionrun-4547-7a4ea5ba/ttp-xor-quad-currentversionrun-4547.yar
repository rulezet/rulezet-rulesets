rule TTP_XOR_QUAD_CurrentVersionRun_4547 {
  strings:
    $key_4547 = { 16 28 [2] 32 26 [2] 19 0a [2] 37 28 [2] 23 33 [2] 2c 29 [2] 32 34 [2] 30 35 [2] 2b 33 [2] 37 34 [2] 2b 1b }

  condition:
    any of them
}