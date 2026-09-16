rule TTP_XOR_QUAD_CurrentVersionRun_ccb0 {
  strings:
    $key_ccb0 = { 9f df [2] bb d1 [2] 90 fd [2] be df [2] aa c4 [2] a5 de [2] bb c3 [2] b9 c2 [2] a2 c4 [2] be c3 [2] a2 ec }

  condition:
    any of them
}