rule TTP_XOR_QUAD_CurrentVersionRun_4517 {
  strings:
    $key_4517 = { 16 78 [2] 32 76 [2] 19 5a [2] 37 78 [2] 23 63 [2] 2c 79 [2] 32 64 [2] 30 65 [2] 2b 63 [2] 37 64 [2] 2b 4b }

  condition:
    any of them
}