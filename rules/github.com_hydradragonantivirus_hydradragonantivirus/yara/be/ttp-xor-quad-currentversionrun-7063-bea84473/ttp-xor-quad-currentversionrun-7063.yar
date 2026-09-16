rule TTP_XOR_QUAD_CurrentVersionRun_7063 {
  strings:
    $key_7063 = { 23 0c [2] 07 02 [2] 2c 2e [2] 02 0c [2] 16 17 [2] 19 0d [2] 07 10 [2] 05 11 [2] 1e 17 [2] 02 10 [2] 1e 3f }

  condition:
    any of them
}