rule TTP_XOR_QUAD_CurrentVersionRun_92bc {
  strings:
    $key_92bc = { c1 d3 [2] e5 dd [2] ce f1 [2] e0 d3 [2] f4 c8 [2] fb d2 [2] e5 cf [2] e7 ce [2] fc c8 [2] e0 cf [2] fc e0 }

  condition:
    any of them
}