rule TTP_XOR_QUAD_CurrentVersionRun_9da8 {
  strings:
    $key_9da8 = { ce c7 [2] ea c9 [2] c1 e5 [2] ef c7 [2] fb dc [2] f4 c6 [2] ea db [2] e8 da [2] f3 dc [2] ef db [2] f3 f4 }

  condition:
    any of them
}