rule TTP_XOR_QUAD_CurrentVersionRun_97e8 {
  strings:
    $key_97e8 = { c4 87 [2] e0 89 [2] cb a5 [2] e5 87 [2] f1 9c [2] fe 86 [2] e0 9b [2] e2 9a [2] f9 9c [2] e5 9b [2] f9 b4 }

  condition:
    any of them
}