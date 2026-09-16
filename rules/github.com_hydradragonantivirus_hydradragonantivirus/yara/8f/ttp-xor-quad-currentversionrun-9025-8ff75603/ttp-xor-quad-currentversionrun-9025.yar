rule TTP_XOR_QUAD_CurrentVersionRun_9025 {
  strings:
    $key_9025 = { c3 4a [2] e7 44 [2] cc 68 [2] e2 4a [2] f6 51 [2] f9 4b [2] e7 56 [2] e5 57 [2] fe 51 [2] e2 56 [2] fe 79 }

  condition:
    any of them
}