rule TTP_XOR_QUAD_CurrentVersionRun_d2ca {
  strings:
    $key_d2ca = { 81 a5 [2] a5 ab [2] 8e 87 [2] a0 a5 [2] b4 be [2] bb a4 [2] a5 b9 [2] a7 b8 [2] bc be [2] a0 b9 [2] bc 96 }

  condition:
    any of them
}