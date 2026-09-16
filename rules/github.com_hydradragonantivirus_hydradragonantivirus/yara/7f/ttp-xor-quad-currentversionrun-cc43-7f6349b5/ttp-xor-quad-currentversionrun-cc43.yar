rule TTP_XOR_QUAD_CurrentVersionRun_cc43 {
  strings:
    $key_cc43 = { 9f 2c [2] bb 22 [2] 90 0e [2] be 2c [2] aa 37 [2] a5 2d [2] bb 30 [2] b9 31 [2] a2 37 [2] be 30 [2] a2 1f }

  condition:
    any of them
}