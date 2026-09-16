rule TTP_XOR_QUAD_CurrentVersionRun_d5ca {
  strings:
    $key_d5ca = { 86 a5 [2] a2 ab [2] 89 87 [2] a7 a5 [2] b3 be [2] bc a4 [2] a2 b9 [2] a0 b8 [2] bb be [2] a7 b9 [2] bb 96 }

  condition:
    any of them
}