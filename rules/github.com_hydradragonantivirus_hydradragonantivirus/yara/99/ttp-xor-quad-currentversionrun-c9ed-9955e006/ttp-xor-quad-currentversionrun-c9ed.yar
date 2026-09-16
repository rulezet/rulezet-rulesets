rule TTP_XOR_QUAD_CurrentVersionRun_c9ed {
  strings:
    $key_c9ed = { 9a 82 [2] be 8c [2] 95 a0 [2] bb 82 [2] af 99 [2] a0 83 [2] be 9e [2] bc 9f [2] a7 99 [2] bb 9e [2] a7 b1 }

  condition:
    any of them
}