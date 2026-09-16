rule TTP_XOR_QUAD_CurrentVersionRun_6db0 {
  strings:
    $key_6db0 = { 3e df [2] 1a d1 [2] 31 fd [2] 1f df [2] 0b c4 [2] 04 de [2] 1a c3 [2] 18 c2 [2] 03 c4 [2] 1f c3 [2] 03 ec }

  condition:
    any of them
}