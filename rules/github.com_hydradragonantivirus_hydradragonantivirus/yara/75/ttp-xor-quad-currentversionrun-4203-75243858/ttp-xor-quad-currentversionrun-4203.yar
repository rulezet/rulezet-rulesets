rule TTP_XOR_QUAD_CurrentVersionRun_4203 {
  strings:
    $key_4203 = { 11 6c [2] 35 62 [2] 1e 4e [2] 30 6c [2] 24 77 [2] 2b 6d [2] 35 70 [2] 37 71 [2] 2c 77 [2] 30 70 [2] 2c 5f }

  condition:
    any of them
}