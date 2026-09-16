rule TTP_XOR_QUAD_CurrentVersionRun_84bc {
  strings:
    $key_84bc = { d7 d3 [2] f3 dd [2] d8 f1 [2] f6 d3 [2] e2 c8 [2] ed d2 [2] f3 cf [2] f1 ce [2] ea c8 [2] f6 cf [2] ea e0 }

  condition:
    any of them
}