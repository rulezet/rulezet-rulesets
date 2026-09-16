rule TTP_XOR_QUAD_CurrentVersionRun_d513 {
  strings:
    $key_d513 = { 86 7c [2] a2 72 [2] 89 5e [2] a7 7c [2] b3 67 [2] bc 7d [2] a2 60 [2] a0 61 [2] bb 67 [2] a7 60 [2] bb 4f }

  condition:
    any of them
}