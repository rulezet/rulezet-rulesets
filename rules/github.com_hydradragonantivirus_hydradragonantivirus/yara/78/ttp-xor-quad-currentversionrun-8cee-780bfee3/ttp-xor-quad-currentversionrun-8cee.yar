rule TTP_XOR_QUAD_CurrentVersionRun_8cee {
  strings:
    $key_8cee = { df 81 [2] fb 8f [2] d0 a3 [2] fe 81 [2] ea 9a [2] e5 80 [2] fb 9d [2] f9 9c [2] e2 9a [2] fe 9d [2] e2 b2 }

  condition:
    any of them
}