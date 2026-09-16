rule TTP_XOR_QUAD_CurrentVersionRun_3043 {
  strings:
    $key_3043 = { 63 2c [2] 47 22 [2] 6c 0e [2] 42 2c [2] 56 37 [2] 59 2d [2] 47 30 [2] 45 31 [2] 5e 37 [2] 42 30 [2] 5e 1f }

  condition:
    any of them
}