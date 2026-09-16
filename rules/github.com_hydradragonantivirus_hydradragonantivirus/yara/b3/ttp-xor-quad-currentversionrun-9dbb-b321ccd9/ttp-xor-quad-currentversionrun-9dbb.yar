rule TTP_XOR_QUAD_CurrentVersionRun_9dbb {
  strings:
    $key_9dbb = { ce d4 [2] ea da [2] c1 f6 [2] ef d4 [2] fb cf [2] f4 d5 [2] ea c8 [2] e8 c9 [2] f3 cf [2] ef c8 [2] f3 e7 }

  condition:
    any of them
}