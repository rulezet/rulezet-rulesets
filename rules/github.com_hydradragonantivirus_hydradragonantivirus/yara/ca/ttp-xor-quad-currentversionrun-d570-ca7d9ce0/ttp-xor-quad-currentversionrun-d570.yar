rule TTP_XOR_QUAD_CurrentVersionRun_d570 {
  strings:
    $key_d570 = { 86 1f [2] a2 11 [2] 89 3d [2] a7 1f [2] b3 04 [2] bc 1e [2] a2 03 [2] a0 02 [2] bb 04 [2] a7 03 [2] bb 2c }

  condition:
    any of them
}