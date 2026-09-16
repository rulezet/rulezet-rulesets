rule TTP_XOR_QUAD_CurrentVersionRun_4557 {
  strings:
    $key_4557 = { 16 38 [2] 32 36 [2] 19 1a [2] 37 38 [2] 23 23 [2] 2c 39 [2] 32 24 [2] 30 25 [2] 2b 23 [2] 37 24 [2] 2b 0b }

  condition:
    any of them
}