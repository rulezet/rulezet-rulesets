rule TTP_XOR_QUAD_CurrentVersionRun_d552 {
  strings:
    $key_d552 = { 86 3d [2] a2 33 [2] 89 1f [2] a7 3d [2] b3 26 [2] bc 3c [2] a2 21 [2] a0 20 [2] bb 26 [2] a7 21 [2] bb 0e }

  condition:
    any of them
}