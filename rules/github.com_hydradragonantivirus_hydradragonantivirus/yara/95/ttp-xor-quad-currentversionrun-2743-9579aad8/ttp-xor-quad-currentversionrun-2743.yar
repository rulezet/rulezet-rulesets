rule TTP_XOR_QUAD_CurrentVersionRun_2743 {
  strings:
    $key_2743 = { 74 2c [2] 50 22 [2] 7b 0e [2] 55 2c [2] 41 37 [2] 4e 2d [2] 50 30 [2] 52 31 [2] 49 37 [2] 55 30 [2] 49 1f }

  condition:
    any of them
}