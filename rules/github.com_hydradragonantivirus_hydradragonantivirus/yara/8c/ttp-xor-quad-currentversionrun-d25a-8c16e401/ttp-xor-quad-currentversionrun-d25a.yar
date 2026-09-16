rule TTP_XOR_QUAD_CurrentVersionRun_d25a {
  strings:
    $key_d25a = { 81 35 [2] a5 3b [2] 8e 17 [2] a0 35 [2] b4 2e [2] bb 34 [2] a5 29 [2] a7 28 [2] bc 2e [2] a0 29 [2] bc 06 }

  condition:
    any of them
}