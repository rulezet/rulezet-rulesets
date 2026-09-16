rule TTP_XOR_QUAD_CurrentVersionRun_972d {
  strings:
    $key_972d = { c4 42 [2] e0 4c [2] cb 60 [2] e5 42 [2] f1 59 [2] fe 43 [2] e0 5e [2] e2 5f [2] f9 59 [2] e5 5e [2] f9 71 }

  condition:
    any of them
}