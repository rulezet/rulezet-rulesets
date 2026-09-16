rule TTP_XOR_QUAD_CurrentVersionRun_11b0 {
  strings:
    $key_11b0 = { 42 df [2] 66 d1 [2] 4d fd [2] 63 df [2] 77 c4 [2] 78 de [2] 66 c3 [2] 64 c2 [2] 7f c4 [2] 63 c3 [2] 7f ec }

  condition:
    any of them
}