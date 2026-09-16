rule TTP_XOR_QUAD_CurrentVersionRun_7073 {
  strings:
    $key_7073 = { 23 1c [2] 07 12 [2] 2c 3e [2] 02 1c [2] 16 07 [2] 19 1d [2] 07 00 [2] 05 01 [2] 1e 07 [2] 02 00 [2] 1e 2f }

  condition:
    any of them
}