rule TTP_XOR_QUAD_CurrentVersionRun_1db0 {
  strings:
    $key_1db0 = { 4e df [2] 6a d1 [2] 41 fd [2] 6f df [2] 7b c4 [2] 74 de [2] 6a c3 [2] 68 c2 [2] 73 c4 [2] 6f c3 [2] 73 ec }

  condition:
    any of them
}