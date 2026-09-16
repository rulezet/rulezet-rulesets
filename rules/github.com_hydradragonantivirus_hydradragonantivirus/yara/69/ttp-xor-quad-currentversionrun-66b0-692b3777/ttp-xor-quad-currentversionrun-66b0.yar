rule TTP_XOR_QUAD_CurrentVersionRun_66b0 {
  strings:
    $key_66b0 = { 35 df [2] 11 d1 [2] 3a fd [2] 14 df [2] 00 c4 [2] 0f de [2] 11 c3 [2] 13 c2 [2] 08 c4 [2] 14 c3 [2] 08 ec }

  condition:
    any of them
}