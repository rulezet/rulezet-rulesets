rule TTP_XOR_QUAD_CurrentVersionRun_c92c {
  strings:
    $key_c92c = { 9a 43 [2] be 4d [2] 95 61 [2] bb 43 [2] af 58 [2] a0 42 [2] be 5f [2] bc 5e [2] a7 58 [2] bb 5f [2] a7 70 }

  condition:
    any of them
}