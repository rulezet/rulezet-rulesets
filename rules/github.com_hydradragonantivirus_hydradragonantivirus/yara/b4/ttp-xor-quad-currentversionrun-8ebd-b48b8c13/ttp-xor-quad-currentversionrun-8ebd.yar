rule TTP_XOR_QUAD_CurrentVersionRun_8ebd {
  strings:
    $key_8ebd = { dd d2 [2] f9 dc [2] d2 f0 [2] fc d2 [2] e8 c9 [2] e7 d3 [2] f9 ce [2] fb cf [2] e0 c9 [2] fc ce [2] e0 e1 }

  condition:
    any of them
}