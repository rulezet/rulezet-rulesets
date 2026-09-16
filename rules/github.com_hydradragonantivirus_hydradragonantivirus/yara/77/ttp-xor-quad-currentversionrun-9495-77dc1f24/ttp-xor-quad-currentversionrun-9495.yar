rule TTP_XOR_QUAD_CurrentVersionRun_9495 {
  strings:
    $key_9495 = { c7 fa [2] e3 f4 [2] c8 d8 [2] e6 fa [2] f2 e1 [2] fd fb [2] e3 e6 [2] e1 e7 [2] fa e1 [2] e6 e6 [2] fa c9 }

  condition:
    any of them
}