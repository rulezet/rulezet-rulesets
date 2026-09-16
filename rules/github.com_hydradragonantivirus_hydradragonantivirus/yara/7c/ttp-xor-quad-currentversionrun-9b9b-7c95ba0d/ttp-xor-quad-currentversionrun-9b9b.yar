rule TTP_XOR_QUAD_CurrentVersionRun_9b9b {
  strings:
    $key_9b9b = { c8 f4 [2] ec fa [2] c7 d6 [2] e9 f4 [2] fd ef [2] f2 f5 [2] ec e8 [2] ee e9 [2] f5 ef [2] e9 e8 [2] f5 c7 }

  condition:
    any of them
}