rule TTP_XOR_QUAD_CurrentVersionRun_ffb0 {
  strings:
    $key_ffb0 = { ac df [2] 88 d1 [2] a3 fd [2] 8d df [2] 99 c4 [2] 96 de [2] 88 c3 [2] 8a c2 [2] 91 c4 [2] 8d c3 [2] 91 ec }

  condition:
    any of them
}