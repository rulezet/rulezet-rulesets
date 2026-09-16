rule TTP_XOR_QUAD_CurrentVersionRun_c9b4 {
  strings:
    $key_c9b4 = { 9a db [2] be d5 [2] 95 f9 [2] bb db [2] af c0 [2] a0 da [2] be c7 [2] bc c6 [2] a7 c0 [2] bb c7 [2] a7 e8 }

  condition:
    any of them
}