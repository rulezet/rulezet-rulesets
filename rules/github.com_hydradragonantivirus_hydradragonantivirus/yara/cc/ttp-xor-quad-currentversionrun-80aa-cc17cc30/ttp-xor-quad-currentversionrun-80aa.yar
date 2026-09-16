rule TTP_XOR_QUAD_CurrentVersionRun_80aa {
  strings:
    $key_80aa = { d3 c5 [2] f7 cb [2] dc e7 [2] f2 c5 [2] e6 de [2] e9 c4 [2] f7 d9 [2] f5 d8 [2] ee de [2] f2 d9 [2] ee f6 }

  condition:
    any of them
}