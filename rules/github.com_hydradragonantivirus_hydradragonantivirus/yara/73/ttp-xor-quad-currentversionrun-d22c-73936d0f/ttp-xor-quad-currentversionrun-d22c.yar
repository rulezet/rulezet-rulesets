rule TTP_XOR_QUAD_CurrentVersionRun_d22c {
  strings:
    $key_d22c = { 81 43 [2] a5 4d [2] 8e 61 [2] a0 43 [2] b4 58 [2] bb 42 [2] a5 5f [2] a7 5e [2] bc 58 [2] a0 5f [2] bc 70 }

  condition:
    any of them
}