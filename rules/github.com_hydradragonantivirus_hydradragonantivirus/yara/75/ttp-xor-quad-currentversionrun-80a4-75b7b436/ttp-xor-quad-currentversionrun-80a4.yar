rule TTP_XOR_QUAD_CurrentVersionRun_80a4 {
  strings:
    $key_80a4 = { d3 cb [2] f7 c5 [2] dc e9 [2] f2 cb [2] e6 d0 [2] e9 ca [2] f7 d7 [2] f5 d6 [2] ee d0 [2] f2 d7 [2] ee f8 }

  condition:
    any of them
}