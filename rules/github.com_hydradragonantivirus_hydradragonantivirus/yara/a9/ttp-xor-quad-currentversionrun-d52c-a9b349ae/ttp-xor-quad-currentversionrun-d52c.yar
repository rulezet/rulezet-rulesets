rule TTP_XOR_QUAD_CurrentVersionRun_d52c {
  strings:
    $key_d52c = { 86 43 [2] a2 4d [2] 89 61 [2] a7 43 [2] b3 58 [2] bc 42 [2] a2 5f [2] a0 5e [2] bb 58 [2] a7 5f [2] bb 70 }

  condition:
    any of them
}