rule TTP_XOR_QUAD_CurrentVersionRun_d25d {
  strings:
    $key_d25d = { 81 32 [2] a5 3c [2] 8e 10 [2] a0 32 [2] b4 29 [2] bb 33 [2] a5 2e [2] a7 2f [2] bc 29 [2] a0 2e [2] bc 01 }

  condition:
    any of them
}