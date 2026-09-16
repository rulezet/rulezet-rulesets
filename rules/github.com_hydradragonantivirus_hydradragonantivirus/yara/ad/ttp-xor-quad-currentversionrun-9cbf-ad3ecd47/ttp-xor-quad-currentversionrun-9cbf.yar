rule TTP_XOR_QUAD_CurrentVersionRun_9cbf {
  strings:
    $key_9cbf = { cf d0 [2] eb de [2] c0 f2 [2] ee d0 [2] fa cb [2] f5 d1 [2] eb cc [2] e9 cd [2] f2 cb [2] ee cc [2] f2 e3 }

  condition:
    any of them
}