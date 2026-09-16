rule TTP_XOR_QUAD_CurrentVersionRun_cea9 {
  strings:
    $key_cea9 = { 9d c6 [2] b9 c8 [2] 92 e4 [2] bc c6 [2] a8 dd [2] a7 c7 [2] b9 da [2] bb db [2] a0 dd [2] bc da [2] a0 f5 }

  condition:
    any of them
}