rule TTP_XOR_QUAD_CurrentVersionRun_975e {
  strings:
    $key_975e = { c4 31 [2] e0 3f [2] cb 13 [2] e5 31 [2] f1 2a [2] fe 30 [2] e0 2d [2] e2 2c [2] f9 2a [2] e5 2d [2] f9 02 }

  condition:
    any of them
}