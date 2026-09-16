rule TTP_XOR_QUAD_CurrentVersionRun_8c3c {
  strings:
    $key_8c3c = { df 53 [2] fb 5d [2] d0 71 [2] fe 53 [2] ea 48 [2] e5 52 [2] fb 4f [2] f9 4e [2] e2 48 [2] fe 4f [2] e2 60 }

  condition:
    any of them
}