rule TTP_XOR_QUAD_CurrentVersionRun_92c6 {
  strings:
    $key_92c6 = { c1 a9 [2] e5 a7 [2] ce 8b [2] e0 a9 [2] f4 b2 [2] fb a8 [2] e5 b5 [2] e7 b4 [2] fc b2 [2] e0 b5 [2] fc 9a }

  condition:
    any of them
}