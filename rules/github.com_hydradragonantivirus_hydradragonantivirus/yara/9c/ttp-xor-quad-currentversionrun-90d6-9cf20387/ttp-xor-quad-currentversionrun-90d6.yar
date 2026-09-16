rule TTP_XOR_QUAD_CurrentVersionRun_90d6 {
  strings:
    $key_90d6 = { c3 b9 [2] e7 b7 [2] cc 9b [2] e2 b9 [2] f6 a2 [2] f9 b8 [2] e7 a5 [2] e5 a4 [2] fe a2 [2] e2 a5 [2] fe 8a }

  condition:
    any of them
}