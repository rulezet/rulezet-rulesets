rule TTP_XOR_QUAD_CurrentVersionRun_d260 {
  strings:
    $key_d260 = { 81 0f [2] a5 01 [2] 8e 2d [2] a0 0f [2] b4 14 [2] bb 0e [2] a5 13 [2] a7 12 [2] bc 14 [2] a0 13 [2] bc 3c }

  condition:
    any of them
}