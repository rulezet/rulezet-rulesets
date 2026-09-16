rule TTP_XOR_QUAD_CurrentVersionRun_ecb0 {
  strings:
    $key_ecb0 = { bf df [2] 9b d1 [2] b0 fd [2] 9e df [2] 8a c4 [2] 85 de [2] 9b c3 [2] 99 c2 [2] 82 c4 [2] 9e c3 [2] 82 ec }

  condition:
    any of them
}