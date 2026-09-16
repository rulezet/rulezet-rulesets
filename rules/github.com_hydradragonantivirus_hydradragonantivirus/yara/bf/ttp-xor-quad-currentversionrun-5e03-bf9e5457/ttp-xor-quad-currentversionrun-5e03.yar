rule TTP_XOR_QUAD_CurrentVersionRun_5e03 {
  strings:
    $key_5e03 = { 0d 6c [2] 29 62 [2] 02 4e [2] 2c 6c [2] 38 77 [2] 37 6d [2] 29 70 [2] 2b 71 [2] 30 77 [2] 2c 70 [2] 30 5f }

  condition:
    any of them
}