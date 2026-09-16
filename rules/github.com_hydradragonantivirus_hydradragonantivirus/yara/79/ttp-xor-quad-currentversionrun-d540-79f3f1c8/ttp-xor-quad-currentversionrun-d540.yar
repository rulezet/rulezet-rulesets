rule TTP_XOR_QUAD_CurrentVersionRun_d540 {
  strings:
    $key_d540 = { 86 2f [2] a2 21 [2] 89 0d [2] a7 2f [2] b3 34 [2] bc 2e [2] a2 33 [2] a0 32 [2] bb 34 [2] a7 33 [2] bb 1c }

  condition:
    any of them
}