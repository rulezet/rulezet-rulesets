rule TTP_XOR_QUAD_CurrentVersionRun_973e {
  strings:
    $key_973e = { c4 51 [2] e0 5f [2] cb 73 [2] e5 51 [2] f1 4a [2] fe 50 [2] e0 4d [2] e2 4c [2] f9 4a [2] e5 4d [2] f9 62 }

  condition:
    any of them
}