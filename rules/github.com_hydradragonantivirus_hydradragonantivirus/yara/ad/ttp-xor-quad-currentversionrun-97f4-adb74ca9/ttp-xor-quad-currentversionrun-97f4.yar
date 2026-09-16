rule TTP_XOR_QUAD_CurrentVersionRun_97f4 {
  strings:
    $key_97f4 = { c4 9b [2] e0 95 [2] cb b9 [2] e5 9b [2] f1 80 [2] fe 9a [2] e0 87 [2] e2 86 [2] f9 80 [2] e5 87 [2] f9 a8 }

  condition:
    any of them
}