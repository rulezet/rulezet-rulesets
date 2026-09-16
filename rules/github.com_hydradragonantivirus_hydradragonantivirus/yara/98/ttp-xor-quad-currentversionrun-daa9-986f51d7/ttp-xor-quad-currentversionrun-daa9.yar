rule TTP_XOR_QUAD_CurrentVersionRun_daa9 {
  strings:
    $key_daa9 = { 89 c6 [2] ad c8 [2] 86 e4 [2] a8 c6 [2] bc dd [2] b3 c7 [2] ad da [2] af db [2] b4 dd [2] a8 da [2] b4 f5 }

  condition:
    any of them
}