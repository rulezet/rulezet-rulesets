rule TTP_XOR_QUAD_CurrentVersionRun_80a2 {
  strings:
    $key_80a2 = { d3 cd [2] f7 c3 [2] dc ef [2] f2 cd [2] e6 d6 [2] e9 cc [2] f7 d1 [2] f5 d0 [2] ee d6 [2] f2 d1 [2] ee fe }

  condition:
    any of them
}