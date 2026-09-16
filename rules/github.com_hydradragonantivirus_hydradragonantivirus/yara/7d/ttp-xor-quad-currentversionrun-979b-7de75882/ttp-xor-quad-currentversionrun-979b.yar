rule TTP_XOR_QUAD_CurrentVersionRun_979b {
  strings:
    $key_979b = { c4 f4 [2] e0 fa [2] cb d6 [2] e5 f4 [2] f1 ef [2] fe f5 [2] e0 e8 [2] e2 e9 [2] f9 ef [2] e5 e8 [2] f9 c7 }

  condition:
    any of them
}