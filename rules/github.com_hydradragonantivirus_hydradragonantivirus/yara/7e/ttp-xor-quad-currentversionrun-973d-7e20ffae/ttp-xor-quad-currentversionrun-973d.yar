rule TTP_XOR_QUAD_CurrentVersionRun_973d {
  strings:
    $key_973d = { c4 52 [2] e0 5c [2] cb 70 [2] e5 52 [2] f1 49 [2] fe 53 [2] e0 4e [2] e2 4f [2] f9 49 [2] e5 4e [2] f9 61 }

  condition:
    any of them
}