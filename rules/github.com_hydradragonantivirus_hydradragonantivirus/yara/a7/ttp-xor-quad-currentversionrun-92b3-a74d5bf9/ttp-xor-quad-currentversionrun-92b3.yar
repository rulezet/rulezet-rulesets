rule TTP_XOR_QUAD_CurrentVersionRun_92b3 {
  strings:
    $key_92b3 = { c1 dc [2] e5 d2 [2] ce fe [2] e0 dc [2] f4 c7 [2] fb dd [2] e5 c0 [2] e7 c1 [2] fc c7 [2] e0 c0 [2] fc ef }

  condition:
    any of them
}