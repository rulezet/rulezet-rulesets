rule TTP_XOR_QUAD_CurrentVersionRun_970f {
  strings:
    $key_970f = { c4 60 [2] e0 6e [2] cb 42 [2] e5 60 [2] f1 7b [2] fe 61 [2] e0 7c [2] e2 7d [2] f9 7b [2] e5 7c [2] f9 53 }

  condition:
    any of them
}