rule TTP_XOR_QUAD_CurrentVersionRun_d213 {
  strings:
    $key_d213 = { 81 7c [2] a5 72 [2] 8e 5e [2] a0 7c [2] b4 67 [2] bb 7d [2] a5 60 [2] a7 61 [2] bc 67 [2] a0 60 [2] bc 4f }

  condition:
    any of them
}