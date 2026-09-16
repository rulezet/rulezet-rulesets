rule TTP_XOR_QUAD_CurrentVersionRun_46b0 {
  strings:
    $key_46b0 = { 15 df [2] 31 d1 [2] 1a fd [2] 34 df [2] 20 c4 [2] 2f de [2] 31 c3 [2] 33 c2 [2] 28 c4 [2] 34 c3 [2] 28 ec }

  condition:
    any of them
}