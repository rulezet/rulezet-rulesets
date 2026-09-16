rule TTP_XOR_QUAD_CurrentVersionRun_97fb {
  strings:
    $key_97fb = { c4 94 [2] e0 9a [2] cb b6 [2] e5 94 [2] f1 8f [2] fe 95 [2] e0 88 [2] e2 89 [2] f9 8f [2] e5 88 [2] f9 a7 }

  condition:
    any of them
}