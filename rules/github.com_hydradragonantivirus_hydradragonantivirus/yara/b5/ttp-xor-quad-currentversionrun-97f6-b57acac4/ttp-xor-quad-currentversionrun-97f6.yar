rule TTP_XOR_QUAD_CurrentVersionRun_97f6 {
  strings:
    $key_97f6 = { c4 99 [2] e0 97 [2] cb bb [2] e5 99 [2] f1 82 [2] fe 98 [2] e0 85 [2] e2 84 [2] f9 82 [2] e5 85 [2] f9 aa }

  condition:
    any of them
}