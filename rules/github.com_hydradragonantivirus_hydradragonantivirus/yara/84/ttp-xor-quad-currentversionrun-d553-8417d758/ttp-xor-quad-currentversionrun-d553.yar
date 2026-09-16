rule TTP_XOR_QUAD_CurrentVersionRun_d553 {
  strings:
    $key_d553 = { 86 3c [2] a2 32 [2] 89 1e [2] a7 3c [2] b3 27 [2] bc 3d [2] a2 20 [2] a0 21 [2] bb 27 [2] a7 20 [2] bb 0f }

  condition:
    any of them
}