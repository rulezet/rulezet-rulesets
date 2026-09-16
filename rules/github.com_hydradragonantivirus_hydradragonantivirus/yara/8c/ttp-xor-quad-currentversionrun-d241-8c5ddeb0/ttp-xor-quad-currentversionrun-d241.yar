rule TTP_XOR_QUAD_CurrentVersionRun_d241 {
  strings:
    $key_d241 = { 81 2e [2] a5 20 [2] 8e 0c [2] a0 2e [2] b4 35 [2] bb 2f [2] a5 32 [2] a7 33 [2] bc 35 [2] a0 32 [2] bc 1d }

  condition:
    any of them
}