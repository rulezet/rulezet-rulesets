rule TTP_XOR_QUAD_CurrentVersionRun_7323 {
  strings:
    $key_7323 = { 20 4c [2] 04 42 [2] 2f 6e [2] 01 4c [2] 15 57 [2] 1a 4d [2] 04 50 [2] 06 51 [2] 1d 57 [2] 01 50 [2] 1d 7f }

  condition:
    any of them
}