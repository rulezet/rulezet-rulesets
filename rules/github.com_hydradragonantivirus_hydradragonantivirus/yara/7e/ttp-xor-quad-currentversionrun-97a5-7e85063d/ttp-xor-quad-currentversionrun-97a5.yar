rule TTP_XOR_QUAD_CurrentVersionRun_97a5 {
  strings:
    $key_97a5 = { c4 ca [2] e0 c4 [2] cb e8 [2] e5 ca [2] f1 d1 [2] fe cb [2] e0 d6 [2] e2 d7 [2] f9 d1 [2] e5 d6 [2] f9 f9 }

  condition:
    any of them
}