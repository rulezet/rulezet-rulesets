rule TTP_XOR_QUAD_CurrentVersionRun_97a6 {
  strings:
    $key_97a6 = { c4 c9 [2] e0 c7 [2] cb eb [2] e5 c9 [2] f1 d2 [2] fe c8 [2] e0 d5 [2] e2 d4 [2] f9 d2 [2] e5 d5 [2] f9 fa }

  condition:
    any of them
}