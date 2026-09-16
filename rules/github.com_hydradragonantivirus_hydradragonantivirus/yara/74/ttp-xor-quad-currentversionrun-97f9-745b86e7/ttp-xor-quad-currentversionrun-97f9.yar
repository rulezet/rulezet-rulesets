rule TTP_XOR_QUAD_CurrentVersionRun_97f9 {
  strings:
    $key_97f9 = { c4 96 [2] e0 98 [2] cb b4 [2] e5 96 [2] f1 8d [2] fe 97 [2] e0 8a [2] e2 8b [2] f9 8d [2] e5 8a [2] f9 a5 }

  condition:
    any of them
}