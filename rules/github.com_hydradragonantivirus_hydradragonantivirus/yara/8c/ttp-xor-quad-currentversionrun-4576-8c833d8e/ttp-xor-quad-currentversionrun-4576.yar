rule TTP_XOR_QUAD_CurrentVersionRun_4576 {
  strings:
    $key_4576 = { 16 19 [2] 32 17 [2] 19 3b [2] 37 19 [2] 23 02 [2] 2c 18 [2] 32 05 [2] 30 04 [2] 2b 02 [2] 37 05 [2] 2b 2a }

  condition:
    any of them
}