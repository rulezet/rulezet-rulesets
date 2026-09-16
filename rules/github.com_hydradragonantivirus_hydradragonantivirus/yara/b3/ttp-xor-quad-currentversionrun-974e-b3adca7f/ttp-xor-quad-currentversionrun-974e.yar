rule TTP_XOR_QUAD_CurrentVersionRun_974e {
  strings:
    $key_974e = { c4 21 [2] e0 2f [2] cb 03 [2] e5 21 [2] f1 3a [2] fe 20 [2] e0 3d [2] e2 3c [2] f9 3a [2] e5 3d [2] f9 12 }

  condition:
    any of them
}