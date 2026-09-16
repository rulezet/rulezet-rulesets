rule TTP_XOR_QUAD_CurrentVersionRun_972e {
  strings:
    $key_972e = { c4 41 [2] e0 4f [2] cb 63 [2] e5 41 [2] f1 5a [2] fe 40 [2] e0 5d [2] e2 5c [2] f9 5a [2] e5 5d [2] f9 72 }

  condition:
    any of them
}