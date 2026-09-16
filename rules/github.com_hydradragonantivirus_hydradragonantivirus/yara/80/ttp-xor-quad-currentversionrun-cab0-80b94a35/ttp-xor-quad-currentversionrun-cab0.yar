rule TTP_XOR_QUAD_CurrentVersionRun_cab0 {
  strings:
    $key_cab0 = { 99 df [2] bd d1 [2] 96 fd [2] b8 df [2] ac c4 [2] a3 de [2] bd c3 [2] bf c2 [2] a4 c4 [2] b8 c3 [2] a4 ec }

  condition:
    any of them
}