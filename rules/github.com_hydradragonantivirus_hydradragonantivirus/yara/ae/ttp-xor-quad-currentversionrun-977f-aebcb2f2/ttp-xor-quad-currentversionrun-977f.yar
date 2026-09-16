rule TTP_XOR_QUAD_CurrentVersionRun_977f {
  strings:
    $key_977f = { c4 10 [2] e0 1e [2] cb 32 [2] e5 10 [2] f1 0b [2] fe 11 [2] e0 0c [2] e2 0d [2] f9 0b [2] e5 0c [2] f9 23 }

  condition:
    any of them
}