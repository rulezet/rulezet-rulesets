rule TTP_XOR_QUAD_CurrentVersionRun_0db0 {
  strings:
    $key_0db0 = { 5e df [2] 7a d1 [2] 51 fd [2] 7f df [2] 6b c4 [2] 64 de [2] 7a c3 [2] 78 c2 [2] 63 c4 [2] 7f c3 [2] 63 ec }

  condition:
    any of them
}