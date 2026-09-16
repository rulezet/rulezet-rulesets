rule TTP_XOR_QUAD_CurrentVersionRun_d563 {
  strings:
    $key_d563 = { 86 0c [2] a2 02 [2] 89 2e [2] a7 0c [2] b3 17 [2] bc 0d [2] a2 10 [2] a0 11 [2] bb 17 [2] a7 10 [2] bb 3f }

  condition:
    any of them
}