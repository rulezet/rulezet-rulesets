rule TTP_XOR_QUAD_CurrentVersionRun_970e {
  strings:
    $key_970e = { c4 61 [2] e0 6f [2] cb 43 [2] e5 61 [2] f1 7a [2] fe 60 [2] e0 7d [2] e2 7c [2] f9 7a [2] e5 7d [2] f9 52 }

  condition:
    any of them
}