rule TTP_XOR_QUAD_CurrentVersionRun_80a3 {
  strings:
    $key_80a3 = { d3 cc [2] f7 c2 [2] dc ee [2] f2 cc [2] e6 d7 [2] e9 cd [2] f7 d0 [2] f5 d1 [2] ee d7 [2] f2 d0 [2] ee ff }

  condition:
    any of them
}