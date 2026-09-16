rule TTP_XOR_QUAD_CurrentVersionRun_88a0 {
  strings:
    $key_88a0 = { db cf [2] ff c1 [2] d4 ed [2] fa cf [2] ee d4 [2] e1 ce [2] ff d3 [2] fd d2 [2] e6 d4 [2] fa d3 [2] e6 fc }

  condition:
    any of them
}