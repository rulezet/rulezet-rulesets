rule TTP_XOR_QUAD_CurrentVersionRun_2bb0 {
  strings:
    $key_2bb0 = { 78 df [2] 5c d1 [2] 77 fd [2] 59 df [2] 4d c4 [2] 42 de [2] 5c c3 [2] 5e c2 [2] 45 c4 [2] 59 c3 [2] 45 ec }

  condition:
    any of them
}