rule TTP_XOR_QUAD_CurrentVersionRun_92d1 {
  strings:
    $key_92d1 = { c1 be [2] e5 b0 [2] ce 9c [2] e0 be [2] f4 a5 [2] fb bf [2] e5 a2 [2] e7 a3 [2] fc a5 [2] e0 a2 [2] fc 8d }

  condition:
    any of them
}