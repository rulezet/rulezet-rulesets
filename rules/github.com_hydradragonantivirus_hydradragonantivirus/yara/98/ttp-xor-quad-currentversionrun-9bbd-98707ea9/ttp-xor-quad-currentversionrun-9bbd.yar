rule TTP_XOR_QUAD_CurrentVersionRun_9bbd {
  strings:
    $key_9bbd = { c8 d2 [2] ec dc [2] c7 f0 [2] e9 d2 [2] fd c9 [2] f2 d3 [2] ec ce [2] ee cf [2] f5 c9 [2] e9 ce [2] f5 e1 }

  condition:
    any of them
}