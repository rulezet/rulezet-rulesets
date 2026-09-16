rule TTP_XOR_QUAD_CurrentVersionRun_92c8 {
  strings:
    $key_92c8 = { c1 a7 [2] e5 a9 [2] ce 85 [2] e0 a7 [2] f4 bc [2] fb a6 [2] e5 bb [2] e7 ba [2] fc bc [2] e0 bb [2] fc 94 }

  condition:
    any of them
}