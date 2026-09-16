rule TTP_XOR_QUAD_CurrentVersionRun_5903 {
  strings:
    $key_5903 = { 0a 6c [2] 2e 62 [2] 05 4e [2] 2b 6c [2] 3f 77 [2] 30 6d [2] 2e 70 [2] 2c 71 [2] 37 77 [2] 2b 70 [2] 37 5f }

  condition:
    any of them
}