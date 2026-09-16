rule TTP_XOR_QUAD_CurrentVersionRun_86bc {
  strings:
    $key_86bc = { d5 d3 [2] f1 dd [2] da f1 [2] f4 d3 [2] e0 c8 [2] ef d2 [2] f1 cf [2] f3 ce [2] e8 c8 [2] f4 cf [2] e8 e0 }

  condition:
    any of them
}