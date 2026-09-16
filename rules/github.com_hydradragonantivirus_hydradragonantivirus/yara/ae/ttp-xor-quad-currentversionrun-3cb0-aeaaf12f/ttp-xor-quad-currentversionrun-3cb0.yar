rule TTP_XOR_QUAD_CurrentVersionRun_3cb0 {
  strings:
    $key_3cb0 = { 6f df [2] 4b d1 [2] 60 fd [2] 4e df [2] 5a c4 [2] 55 de [2] 4b c3 [2] 49 c2 [2] 52 c4 [2] 4e c3 [2] 52 ec }

  condition:
    any of them
}