rule TTP_XOR_QUAD_CurrentVersionRun_2443 {
  strings:
    $key_2443 = { 77 2c [2] 53 22 [2] 78 0e [2] 56 2c [2] 42 37 [2] 4d 2d [2] 53 30 [2] 51 31 [2] 4a 37 [2] 56 30 [2] 4a 1f }

  condition:
    any of them
}