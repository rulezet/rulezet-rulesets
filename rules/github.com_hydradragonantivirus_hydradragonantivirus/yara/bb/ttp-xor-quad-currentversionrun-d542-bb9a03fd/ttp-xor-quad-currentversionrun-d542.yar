rule TTP_XOR_QUAD_CurrentVersionRun_d542 {
  strings:
    $key_d542 = { 86 2d [2] a2 23 [2] 89 0f [2] a7 2d [2] b3 36 [2] bc 2c [2] a2 31 [2] a0 30 [2] bb 36 [2] a7 31 [2] bb 1e }

  condition:
    any of them
}