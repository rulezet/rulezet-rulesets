rule TTP_XOR_QUAD_CurrentVersionRun_97ea {
  strings:
    $key_97ea = { c4 85 [2] e0 8b [2] cb a7 [2] e5 85 [2] f1 9e [2] fe 84 [2] e0 99 [2] e2 98 [2] f9 9e [2] e5 99 [2] f9 b6 }

  condition:
    any of them
}