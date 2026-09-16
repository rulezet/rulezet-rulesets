rule TTP_XOR_QUAD_CurrentVersionRun_977e {
  strings:
    $key_977e = { c4 11 [2] e0 1f [2] cb 33 [2] e5 11 [2] f1 0a [2] fe 10 [2] e0 0d [2] e2 0c [2] f9 0a [2] e5 0d [2] f9 22 }

  condition:
    any of them
}