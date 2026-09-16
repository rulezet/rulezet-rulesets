rule TTP_XOR_QUAD_CurrentVersionRun_92bf {
  strings:
    $key_92bf = { c1 d0 [2] e5 de [2] ce f2 [2] e0 d0 [2] f4 cb [2] fb d1 [2] e5 cc [2] e7 cd [2] fc cb [2] e0 cc [2] fc e3 }

  condition:
    any of them
}