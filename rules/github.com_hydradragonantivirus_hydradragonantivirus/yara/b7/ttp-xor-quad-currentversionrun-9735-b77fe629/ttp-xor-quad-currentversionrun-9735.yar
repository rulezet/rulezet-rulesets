rule TTP_XOR_QUAD_CurrentVersionRun_9735 {
  strings:
    $key_9735 = { c4 5a [2] e0 54 [2] cb 78 [2] e5 5a [2] f1 41 [2] fe 5b [2] e0 46 [2] e2 47 [2] f9 41 [2] e5 46 [2] f9 69 }

  condition:
    any of them
}