rule TTP_XOR_QUAD_CurrentVersionRun_956e {
  strings:
    $key_956e = { c6 01 [2] e2 0f [2] c9 23 [2] e7 01 [2] f3 1a [2] fc 00 [2] e2 1d [2] e0 1c [2] fb 1a [2] e7 1d [2] fb 32 }

  condition:
    any of them
}