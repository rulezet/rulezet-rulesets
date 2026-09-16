rule TTP_XOR_QUAD_CurrentVersionRun_97e7 {
  strings:
    $key_97e7 = { c4 88 [2] e0 86 [2] cb aa [2] e5 88 [2] f1 93 [2] fe 89 [2] e0 94 [2] e2 95 [2] f9 93 [2] e5 94 [2] f9 bb }

  condition:
    any of them
}