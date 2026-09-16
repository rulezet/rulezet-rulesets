rule TTP_XOR_QUAD_CurrentVersionRun_c963 {
  strings:
    $key_c963 = { 9a 0c [2] be 02 [2] 95 2e [2] bb 0c [2] af 17 [2] a0 0d [2] be 10 [2] bc 11 [2] a7 17 [2] bb 10 [2] a7 3f }

  condition:
    any of them
}