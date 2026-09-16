rule TTP_XOR_QUAD_CurrentVersionRun_c9a9 {
  strings:
    $key_c9a9 = { 9a c6 [2] be c8 [2] 95 e4 [2] bb c6 [2] af dd [2] a0 c7 [2] be da [2] bc db [2] a7 dd [2] bb da [2] a7 f5 }

  condition:
    any of them
}