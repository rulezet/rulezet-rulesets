rule TTP_XOR_QUAD_CurrentVersionRun_974f {
  strings:
    $key_974f = { c4 20 [2] e0 2e [2] cb 02 [2] e5 20 [2] f1 3b [2] fe 21 [2] e0 3c [2] e2 3d [2] f9 3b [2] e5 3c [2] f9 13 }

  condition:
    any of them
}