rule TTP_XOR_QUAD_CurrentVersionRun_970b {
  strings:
    $key_970b = { c4 64 [2] e0 6a [2] cb 46 [2] e5 64 [2] f1 7f [2] fe 65 [2] e0 78 [2] e2 79 [2] f9 7f [2] e5 78 [2] f9 57 }

  condition:
    any of them
}