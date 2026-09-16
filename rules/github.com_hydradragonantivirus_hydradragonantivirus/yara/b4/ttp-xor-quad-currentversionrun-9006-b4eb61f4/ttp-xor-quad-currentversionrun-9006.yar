rule TTP_XOR_QUAD_CurrentVersionRun_9006 {
  strings:
    $key_9006 = { c3 69 [2] e7 67 [2] cc 4b [2] e2 69 [2] f6 72 [2] f9 68 [2] e7 75 [2] e5 74 [2] fe 72 [2] e2 75 [2] fe 5a }

  condition:
    any of them
}