rule TTP_XOR_QUAD_CurrentVersionRun_97b8 {
  strings:
    $key_97b8 = { c4 d7 [2] e0 d9 [2] cb f5 [2] e5 d7 [2] f1 cc [2] fe d6 [2] e0 cb [2] e2 ca [2] f9 cc [2] e5 cb [2] f9 e4 }

  condition:
    any of them
}