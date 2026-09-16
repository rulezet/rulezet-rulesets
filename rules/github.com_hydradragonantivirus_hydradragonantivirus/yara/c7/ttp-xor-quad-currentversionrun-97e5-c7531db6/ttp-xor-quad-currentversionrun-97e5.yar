rule TTP_XOR_QUAD_CurrentVersionRun_97e5 {
  strings:
    $key_97e5 = { c4 8a [2] e0 84 [2] cb a8 [2] e5 8a [2] f1 91 [2] fe 8b [2] e0 96 [2] e2 97 [2] f9 91 [2] e5 96 [2] f9 b9 }

  condition:
    any of them
}