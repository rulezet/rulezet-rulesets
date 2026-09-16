rule TTP_XOR_QUAD_CurrentVersionRun_2db0 {
  strings:
    $key_2db0 = { 7e df [2] 5a d1 [2] 71 fd [2] 5f df [2] 4b c4 [2] 44 de [2] 5a c3 [2] 58 c2 [2] 43 c4 [2] 5f c3 [2] 43 ec }

  condition:
    any of them
}