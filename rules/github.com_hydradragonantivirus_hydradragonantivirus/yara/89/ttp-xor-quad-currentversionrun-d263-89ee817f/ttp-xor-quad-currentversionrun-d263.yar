rule TTP_XOR_QUAD_CurrentVersionRun_d263 {
  strings:
    $key_d263 = { 81 0c [2] a5 02 [2] 8e 2e [2] a0 0c [2] b4 17 [2] bb 0d [2] a5 10 [2] a7 11 [2] bc 17 [2] a0 10 [2] bc 3f }

  condition:
    any of them
}