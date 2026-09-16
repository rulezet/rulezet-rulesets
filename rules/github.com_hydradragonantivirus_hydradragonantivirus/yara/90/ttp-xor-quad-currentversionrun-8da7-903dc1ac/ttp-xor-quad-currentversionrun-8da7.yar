rule TTP_XOR_QUAD_CurrentVersionRun_8da7 {
  strings:
    $key_8da7 = { de c8 [2] fa c6 [2] d1 ea [2] ff c8 [2] eb d3 [2] e4 c9 [2] fa d4 [2] f8 d5 [2] e3 d3 [2] ff d4 [2] e3 fb }

  condition:
    any of them
}