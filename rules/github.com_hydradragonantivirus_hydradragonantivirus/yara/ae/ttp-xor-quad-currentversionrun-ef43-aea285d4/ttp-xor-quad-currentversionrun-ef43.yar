rule TTP_XOR_QUAD_CurrentVersionRun_ef43 {
  strings:
    $key_ef43 = { bc 2c [2] 98 22 [2] b3 0e [2] 9d 2c [2] 89 37 [2] 86 2d [2] 98 30 [2] 9a 31 [2] 81 37 [2] 9d 30 [2] 81 1f }

  condition:
    any of them
}