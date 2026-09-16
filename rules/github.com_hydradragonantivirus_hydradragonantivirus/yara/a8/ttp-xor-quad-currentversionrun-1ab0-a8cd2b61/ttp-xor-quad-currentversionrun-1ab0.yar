rule TTP_XOR_QUAD_CurrentVersionRun_1ab0 {
  strings:
    $key_1ab0 = { 49 df [2] 6d d1 [2] 46 fd [2] 68 df [2] 7c c4 [2] 73 de [2] 6d c3 [2] 6f c2 [2] 74 c4 [2] 68 c3 [2] 74 ec }

  condition:
    any of them
}