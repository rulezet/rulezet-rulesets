rule TTP_XOR_QUAD_CurrentVersionRun_9795 {
  strings:
    $key_9795 = { c4 fa [2] e0 f4 [2] cb d8 [2] e5 fa [2] f1 e1 [2] fe fb [2] e0 e6 [2] e2 e7 [2] f9 e1 [2] e5 e6 [2] f9 c9 }

  condition:
    any of them
}