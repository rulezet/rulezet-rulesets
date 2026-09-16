rule TTP_XOR_QUAD_CurrentVersionRun_c940 {
  strings:
    $key_c940 = { 9a 2f [2] be 21 [2] 95 0d [2] bb 2f [2] af 34 [2] a0 2e [2] be 33 [2] bc 32 [2] a7 34 [2] bb 33 [2] a7 1c }

  condition:
    any of them
}