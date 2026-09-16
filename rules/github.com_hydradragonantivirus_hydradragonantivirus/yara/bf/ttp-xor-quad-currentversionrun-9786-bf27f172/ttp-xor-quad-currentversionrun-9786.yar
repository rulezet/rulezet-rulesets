rule TTP_XOR_QUAD_CurrentVersionRun_9786 {
  strings:
    $key_9786 = { c4 e9 [2] e0 e7 [2] cb cb [2] e5 e9 [2] f1 f2 [2] fe e8 [2] e0 f5 [2] e2 f4 [2] f9 f2 [2] e5 f5 [2] f9 da }

  condition:
    any of them
}