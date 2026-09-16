rule TTP_XOR_QUAD_CurrentVersionRun_92aa {
  strings:
    $key_92aa = { c1 c5 [2] e5 cb [2] ce e7 [2] e0 c5 [2] f4 de [2] fb c4 [2] e5 d9 [2] e7 d8 [2] fc de [2] e0 d9 [2] fc f6 }

  condition:
    any of them
}