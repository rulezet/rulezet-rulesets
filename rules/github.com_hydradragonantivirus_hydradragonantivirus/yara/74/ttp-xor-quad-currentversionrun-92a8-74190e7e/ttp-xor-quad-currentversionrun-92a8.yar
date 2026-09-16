rule TTP_XOR_QUAD_CurrentVersionRun_92a8 {
  strings:
    $key_92a8 = { c1 c7 [2] e5 c9 [2] ce e5 [2] e0 c7 [2] f4 dc [2] fb c6 [2] e5 db [2] e7 da [2] fc dc [2] e0 db [2] fc f4 }

  condition:
    any of them
}