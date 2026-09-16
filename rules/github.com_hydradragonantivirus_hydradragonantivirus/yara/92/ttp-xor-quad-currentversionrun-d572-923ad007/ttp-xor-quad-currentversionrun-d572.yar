rule TTP_XOR_QUAD_CurrentVersionRun_d572 {
  strings:
    $key_d572 = { 86 1d [2] a2 13 [2] 89 3f [2] a7 1d [2] b3 06 [2] bc 1c [2] a2 01 [2] a0 00 [2] bb 06 [2] a7 01 [2] bb 2e }

  condition:
    any of them
}