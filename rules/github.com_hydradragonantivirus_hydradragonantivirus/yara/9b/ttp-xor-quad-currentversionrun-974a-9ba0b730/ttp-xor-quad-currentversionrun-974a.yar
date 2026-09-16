rule TTP_XOR_QUAD_CurrentVersionRun_974a {
  strings:
    $key_974a = { c4 25 [2] e0 2b [2] cb 07 [2] e5 25 [2] f1 3e [2] fe 24 [2] e0 39 [2] e2 38 [2] f9 3e [2] e5 39 [2] f9 16 }

  condition:
    any of them
}