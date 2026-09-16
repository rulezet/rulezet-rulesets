rule TTP_XOR_QUAD_CurrentVersionRun_a2b0 {
  strings:
    $key_a2b0 = { f1 df [2] d5 d1 [2] fe fd [2] d0 df [2] c4 c4 [2] cb de [2] d5 c3 [2] d7 c2 [2] cc c4 [2] d0 c3 [2] cc ec }

  condition:
    any of them
}