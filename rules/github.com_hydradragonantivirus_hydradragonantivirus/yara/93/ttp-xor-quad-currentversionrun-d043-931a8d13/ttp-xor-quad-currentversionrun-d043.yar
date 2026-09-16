rule TTP_XOR_QUAD_CurrentVersionRun_d043 {
  strings:
    $key_d043 = { 83 2c [2] a7 22 [2] 8c 0e [2] a2 2c [2] b6 37 [2] b9 2d [2] a7 30 [2] a5 31 [2] be 37 [2] a2 30 [2] be 1f }

  condition:
    any of them
}