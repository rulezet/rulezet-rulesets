rule TTP_XOR_QUAD_CurrentVersionRun_97ba {
  strings:
    $key_97ba = { c4 d5 [2] e0 db [2] cb f7 [2] e5 d5 [2] f1 ce [2] fe d4 [2] e0 c9 [2] e2 c8 [2] f9 ce [2] e5 c9 [2] f9 e6 }

  condition:
    any of them
}