rule TTP_XOR_QUAD_CurrentVersionRun_88a7 {
  strings:
    $key_88a7 = { db c8 [2] ff c6 [2] d4 ea [2] fa c8 [2] ee d3 [2] e1 c9 [2] ff d4 [2] fd d5 [2] e6 d3 [2] fa d4 [2] e6 fb }

  condition:
    any of them
}