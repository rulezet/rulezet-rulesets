rule TTP_XOR_QUAD_CurrentVersionRun_9772 {
  strings:
    $key_9772 = { c4 1d [2] e0 13 [2] cb 3f [2] e5 1d [2] f1 06 [2] fe 1c [2] e0 01 [2] e2 00 [2] f9 06 [2] e5 01 [2] f9 2e }

  condition:
    any of them
}