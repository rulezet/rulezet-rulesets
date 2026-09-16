rule TTP_XOR_QUAD_CurrentVersionRun_9047 {
  strings:
    $key_9047 = { c3 28 [2] e7 26 [2] cc 0a [2] e2 28 [2] f6 33 [2] f9 29 [2] e7 34 [2] e5 35 [2] fe 33 [2] e2 34 [2] fe 1b }

  condition:
    any of them
}