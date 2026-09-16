rule TTP_XOR_QUAD_CurrentVersionRun_90d4 {
  strings:
    $key_90d4 = { c3 bb [2] e7 b5 [2] cc 99 [2] e2 bb [2] f6 a0 [2] f9 ba [2] e7 a7 [2] e5 a6 [2] fe a0 [2] e2 a7 [2] fe 88 }

  condition:
    any of them
}