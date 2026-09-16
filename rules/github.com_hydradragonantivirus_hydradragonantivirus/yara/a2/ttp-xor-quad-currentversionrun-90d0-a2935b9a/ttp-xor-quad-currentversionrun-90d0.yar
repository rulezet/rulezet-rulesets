rule TTP_XOR_QUAD_CurrentVersionRun_90d0 {
  strings:
    $key_90d0 = { c3 bf [2] e7 b1 [2] cc 9d [2] e2 bf [2] f6 a4 [2] f9 be [2] e7 a3 [2] e5 a2 [2] fe a4 [2] e2 a3 [2] fe 8c }

  condition:
    any of them
}