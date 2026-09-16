rule TTP_XOR_QUAD_CurrentVersionRun_56b0 {
  strings:
    $key_56b0 = { 05 df [2] 21 d1 [2] 0a fd [2] 24 df [2] 30 c4 [2] 3f de [2] 21 c3 [2] 23 c2 [2] 38 c4 [2] 24 c3 [2] 38 ec }

  condition:
    any of them
}