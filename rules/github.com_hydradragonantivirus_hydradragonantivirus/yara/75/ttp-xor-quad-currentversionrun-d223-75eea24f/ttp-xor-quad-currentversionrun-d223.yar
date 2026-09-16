rule TTP_XOR_QUAD_CurrentVersionRun_d223 {
  strings:
    $key_d223 = { 81 4c [2] a5 42 [2] 8e 6e [2] a0 4c [2] b4 57 [2] bb 4d [2] a5 50 [2] a7 51 [2] bc 57 [2] a0 50 [2] bc 7f }

  condition:
    any of them
}