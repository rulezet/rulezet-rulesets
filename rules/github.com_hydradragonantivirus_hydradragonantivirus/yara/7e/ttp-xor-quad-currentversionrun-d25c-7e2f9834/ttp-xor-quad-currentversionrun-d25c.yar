rule TTP_XOR_QUAD_CurrentVersionRun_d25c {
  strings:
    $key_d25c = { 81 33 [2] a5 3d [2] 8e 11 [2] a0 33 [2] b4 28 [2] bb 32 [2] a5 2f [2] a7 2e [2] bc 28 [2] a0 2f [2] bc 00 }

  condition:
    any of them
}