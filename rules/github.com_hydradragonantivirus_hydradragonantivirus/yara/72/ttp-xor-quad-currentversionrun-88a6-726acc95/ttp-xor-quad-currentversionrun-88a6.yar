rule TTP_XOR_QUAD_CurrentVersionRun_88a6 {
  strings:
    $key_88a6 = { db c9 [2] ff c7 [2] d4 eb [2] fa c9 [2] ee d2 [2] e1 c8 [2] ff d5 [2] fd d4 [2] e6 d2 [2] fa d5 [2] e6 fa }

  condition:
    any of them
}