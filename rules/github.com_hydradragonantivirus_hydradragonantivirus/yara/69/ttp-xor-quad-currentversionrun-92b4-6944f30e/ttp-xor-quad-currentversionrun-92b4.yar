rule TTP_XOR_QUAD_CurrentVersionRun_92b4 {
  strings:
    $key_92b4 = { c1 db [2] e5 d5 [2] ce f9 [2] e0 db [2] f4 c0 [2] fb da [2] e5 c7 [2] e7 c6 [2] fc c0 [2] e0 c7 [2] fc e8 }

  condition:
    any of them
}