rule TTP_XOR_QUAD_CurrentVersionRun_905a {
  strings:
    $key_905a = { c3 35 [2] e7 3b [2] cc 17 [2] e2 35 [2] f6 2e [2] f9 34 [2] e7 29 [2] e5 28 [2] fe 2e [2] e2 29 [2] fe 06 }

  condition:
    any of them
}