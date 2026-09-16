rule TTP_XOR_QUAD_CurrentVersionRun_d2a9 {
  strings:
    $key_d2a9 = { 81 c6 [2] a5 c8 [2] 8e e4 [2] a0 c6 [2] b4 dd [2] bb c7 [2] a5 da [2] a7 db [2] bc dd [2] a0 da [2] bc f5 }

  condition:
    any of them
}