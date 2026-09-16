rule TTP_XOR_QUAD_CurrentVersionRun_c930 {
  strings:
    $key_c930 = { 9a 5f [2] be 51 [2] 95 7d [2] bb 5f [2] af 44 [2] a0 5e [2] be 43 [2] bc 42 [2] a7 44 [2] bb 43 [2] a7 6c }

  condition:
    any of them
}