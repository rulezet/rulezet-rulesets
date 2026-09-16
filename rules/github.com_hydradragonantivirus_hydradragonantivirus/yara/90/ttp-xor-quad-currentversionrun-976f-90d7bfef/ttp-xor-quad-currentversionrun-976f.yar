rule TTP_XOR_QUAD_CurrentVersionRun_976f {
  strings:
    $key_976f = { c4 00 [2] e0 0e [2] cb 22 [2] e5 00 [2] f1 1b [2] fe 01 [2] e0 1c [2] e2 1d [2] f9 1b [2] e5 1c [2] f9 33 }

  condition:
    any of them
}