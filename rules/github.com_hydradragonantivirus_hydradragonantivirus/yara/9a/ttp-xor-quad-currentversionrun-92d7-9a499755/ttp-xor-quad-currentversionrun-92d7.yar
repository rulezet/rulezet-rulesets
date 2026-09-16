rule TTP_XOR_QUAD_CurrentVersionRun_92d7 {
  strings:
    $key_92d7 = { c1 b8 [2] e5 b6 [2] ce 9a [2] e0 b8 [2] f4 a3 [2] fb b9 [2] e5 a4 [2] e7 a5 [2] fc a3 [2] e0 a4 [2] fc 8b }

  condition:
    any of them
}