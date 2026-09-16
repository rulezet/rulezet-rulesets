rule TTP_XOR_QUAD_CurrentVersionRun_8083 {
  strings:
    $key_8083 = { d3 ec [2] f7 e2 [2] dc ce [2] f2 ec [2] e6 f7 [2] e9 ed [2] f7 f0 [2] f5 f1 [2] ee f7 [2] f2 f0 [2] ee df }

  condition:
    any of them
}