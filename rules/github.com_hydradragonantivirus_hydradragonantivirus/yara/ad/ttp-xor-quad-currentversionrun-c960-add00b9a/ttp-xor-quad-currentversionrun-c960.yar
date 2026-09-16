rule TTP_XOR_QUAD_CurrentVersionRun_c960 {
  strings:
    $key_c960 = { 9a 0f [2] be 01 [2] 95 2d [2] bb 0f [2] af 14 [2] a0 0e [2] be 13 [2] bc 12 [2] a7 14 [2] bb 13 [2] a7 3c }

  condition:
    any of them
}