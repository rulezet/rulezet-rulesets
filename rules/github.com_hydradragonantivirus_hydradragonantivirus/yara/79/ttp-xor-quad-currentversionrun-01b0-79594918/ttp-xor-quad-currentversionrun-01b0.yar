rule TTP_XOR_QUAD_CurrentVersionRun_01b0 {
  strings:
    $key_01b0 = { 52 df [2] 76 d1 [2] 5d fd [2] 73 df [2] 67 c4 [2] 68 de [2] 76 c3 [2] 74 c2 [2] 6f c4 [2] 73 c3 [2] 6f ec }

  condition:
    any of them
}