rule TTP_XOR_QUAD_CurrentVersionRun_92d5 {
  strings:
    $key_92d5 = { c1 ba [2] e5 b4 [2] ce 98 [2] e0 ba [2] f4 a1 [2] fb bb [2] e5 a6 [2] e7 a7 [2] fc a1 [2] e0 a6 [2] fc 89 }

  condition:
    any of them
}