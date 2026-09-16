rule TTP_XOR_QUAD_CurrentVersionRun_2b43 {
  strings:
    $key_2b43 = { 78 2c [2] 5c 22 [2] 77 0e [2] 59 2c [2] 4d 37 [2] 42 2d [2] 5c 30 [2] 5e 31 [2] 45 37 [2] 59 30 [2] 45 1f }

  condition:
    any of them
}