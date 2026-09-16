rule TTP_XOR_QUAD_CurrentVersionRun_90d7 {
  strings:
    $key_90d7 = { c3 b8 [2] e7 b6 [2] cc 9a [2] e2 b8 [2] f6 a3 [2] f9 b9 [2] e7 a4 [2] e5 a5 [2] fe a3 [2] e2 a4 [2] fe 8b }

  condition:
    any of them
}