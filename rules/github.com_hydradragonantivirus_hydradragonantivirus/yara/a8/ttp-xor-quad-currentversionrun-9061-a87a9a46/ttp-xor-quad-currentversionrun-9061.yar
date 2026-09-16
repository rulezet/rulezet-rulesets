rule TTP_XOR_QUAD_CurrentVersionRun_9061 {
  strings:
    $key_9061 = { c3 0e [2] e7 00 [2] cc 2c [2] e2 0e [2] f6 15 [2] f9 0f [2] e7 12 [2] e5 13 [2] fe 15 [2] e2 12 [2] fe 3d }

  condition:
    any of them
}