rule TTP_XOR_QUAD_CurrentVersionRun_92a4 {
  strings:
    $key_92a4 = { c1 cb [2] e5 c5 [2] ce e9 [2] e0 cb [2] f4 d0 [2] fb ca [2] e5 d7 [2] e7 d6 [2] fc d0 [2] e0 d7 [2] fc f8 }

  condition:
    any of them
}