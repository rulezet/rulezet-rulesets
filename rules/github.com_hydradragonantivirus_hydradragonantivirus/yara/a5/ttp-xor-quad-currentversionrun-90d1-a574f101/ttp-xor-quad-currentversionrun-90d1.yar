rule TTP_XOR_QUAD_CurrentVersionRun_90d1 {
  strings:
    $key_90d1 = { c3 be [2] e7 b0 [2] cc 9c [2] e2 be [2] f6 a5 [2] f9 bf [2] e7 a2 [2] e5 a3 [2] fe a5 [2] e2 a2 [2] fe 8d }

  condition:
    any of them
}