rule TTP_XOR_QUAD_CurrentVersionRun_cbb0 {
  strings:
    $key_cbb0 = { 98 df [2] bc d1 [2] 97 fd [2] b9 df [2] ad c4 [2] a2 de [2] bc c3 [2] be c2 [2] a5 c4 [2] b9 c3 [2] a5 ec }

  condition:
    any of them
}