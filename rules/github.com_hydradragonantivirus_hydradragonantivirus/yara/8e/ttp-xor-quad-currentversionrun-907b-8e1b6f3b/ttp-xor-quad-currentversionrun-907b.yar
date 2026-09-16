rule TTP_XOR_QUAD_CurrentVersionRun_907b {
  strings:
    $key_907b = { c3 14 [2] e7 1a [2] cc 36 [2] e2 14 [2] f6 0f [2] f9 15 [2] e7 08 [2] e5 09 [2] fe 0f [2] e2 08 [2] fe 27 }

  condition:
    any of them
}