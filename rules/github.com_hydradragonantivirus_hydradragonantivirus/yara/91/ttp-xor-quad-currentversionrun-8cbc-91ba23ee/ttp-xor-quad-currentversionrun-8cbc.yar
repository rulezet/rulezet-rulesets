rule TTP_XOR_QUAD_CurrentVersionRun_8cbc {
  strings:
    $key_8cbc = { df d3 [2] fb dd [2] d0 f1 [2] fe d3 [2] ea c8 [2] e5 d2 [2] fb cf [2] f9 ce [2] e2 c8 [2] fe cf [2] e2 e0 }

  condition:
    any of them
}