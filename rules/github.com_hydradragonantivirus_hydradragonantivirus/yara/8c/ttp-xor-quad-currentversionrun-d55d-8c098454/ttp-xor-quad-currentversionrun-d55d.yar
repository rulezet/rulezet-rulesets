rule TTP_XOR_QUAD_CurrentVersionRun_d55d {
  strings:
    $key_d55d = { 86 32 [2] a2 3c [2] 89 10 [2] a7 32 [2] b3 29 [2] bc 33 [2] a2 2e [2] a0 2f [2] bb 29 [2] a7 2e [2] bb 01 }

  condition:
    any of them
}