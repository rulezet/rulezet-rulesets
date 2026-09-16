rule TTP_XOR_QUAD_CurrentVersionRun_21b0 {
  strings:
    $key_21b0 = { 72 df [2] 56 d1 [2] 7d fd [2] 53 df [2] 47 c4 [2] 48 de [2] 56 c3 [2] 54 c2 [2] 4f c4 [2] 53 c3 [2] 4f ec }

  condition:
    any of them
}