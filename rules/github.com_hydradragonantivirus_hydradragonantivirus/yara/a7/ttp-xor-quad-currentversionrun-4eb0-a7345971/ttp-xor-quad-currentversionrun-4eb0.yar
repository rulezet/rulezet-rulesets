rule TTP_XOR_QUAD_CurrentVersionRun_4eb0 {
  strings:
    $key_4eb0 = { 1d df [2] 39 d1 [2] 12 fd [2] 3c df [2] 28 c4 [2] 27 de [2] 39 c3 [2] 3b c2 [2] 20 c4 [2] 3c c3 [2] 20 ec }

  condition:
    any of them
}