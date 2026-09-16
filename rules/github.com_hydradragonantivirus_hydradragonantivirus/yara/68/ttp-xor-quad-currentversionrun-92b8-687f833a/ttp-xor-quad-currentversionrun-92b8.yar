rule TTP_XOR_QUAD_CurrentVersionRun_92b8 {
  strings:
    $key_92b8 = { c1 d7 [2] e5 d9 [2] ce f5 [2] e0 d7 [2] f4 cc [2] fb d6 [2] e5 cb [2] e7 ca [2] fc cc [2] e0 cb [2] fc e4 }

  condition:
    any of them
}