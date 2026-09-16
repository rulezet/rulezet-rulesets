rule TTP_XOR_QUAD_CurrentVersionRun_970c {
  strings:
    $key_970c = { c4 63 [2] e0 6d [2] cb 41 [2] e5 63 [2] f1 78 [2] fe 62 [2] e0 7f [2] e2 7e [2] f9 78 [2] e5 7f [2] f9 50 }

  condition:
    any of them
}