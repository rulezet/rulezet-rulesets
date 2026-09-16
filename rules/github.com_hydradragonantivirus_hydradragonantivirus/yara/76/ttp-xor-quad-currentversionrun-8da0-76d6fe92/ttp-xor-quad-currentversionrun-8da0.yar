rule TTP_XOR_QUAD_CurrentVersionRun_8da0 {
  strings:
    $key_8da0 = { de cf [2] fa c1 [2] d1 ed [2] ff cf [2] eb d4 [2] e4 ce [2] fa d3 [2] f8 d2 [2] e3 d4 [2] ff d3 [2] e3 fc }

  condition:
    any of them
}