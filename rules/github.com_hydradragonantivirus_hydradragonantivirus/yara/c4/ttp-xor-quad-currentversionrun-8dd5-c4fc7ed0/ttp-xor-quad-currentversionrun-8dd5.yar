rule TTP_XOR_QUAD_CurrentVersionRun_8dd5 {
  strings:
    $key_8dd5 = { de ba [2] fa b4 [2] d1 98 [2] ff ba [2] eb a1 [2] e4 bb [2] fa a6 [2] f8 a7 [2] e3 a1 [2] ff a6 [2] e3 89 }

  condition:
    any of them
}