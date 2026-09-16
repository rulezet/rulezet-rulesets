rule TTP_XOR_QUAD_CurrentVersionRun_978b {
  strings:
    $key_978b = { c4 e4 [2] e0 ea [2] cb c6 [2] e5 e4 [2] f1 ff [2] fe e5 [2] e0 f8 [2] e2 f9 [2] f9 ff [2] e5 f8 [2] f9 d7 }

  condition:
    any of them
}