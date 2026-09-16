rule TTP_XOR_QUAD_CurrentVersionRun_6ab0 {
  strings:
    $key_6ab0 = { 39 df [2] 1d d1 [2] 36 fd [2] 18 df [2] 0c c4 [2] 03 de [2] 1d c3 [2] 1f c2 [2] 04 c4 [2] 18 c3 [2] 04 ec }

  condition:
    any of them
}