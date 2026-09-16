rule TTP_XOR_QUAD_CurrentVersionRun_9a94 {
  strings:
    $key_9a94 = { c9 fb [2] ed f5 [2] c6 d9 [2] e8 fb [2] fc e0 [2] f3 fa [2] ed e7 [2] ef e6 [2] f4 e0 [2] e8 e7 [2] f4 c8 }

  condition:
    any of them
}