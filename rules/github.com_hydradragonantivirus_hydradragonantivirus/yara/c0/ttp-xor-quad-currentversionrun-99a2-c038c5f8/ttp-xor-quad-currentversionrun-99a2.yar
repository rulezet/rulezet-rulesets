rule TTP_XOR_QUAD_CurrentVersionRun_99a2 {
  strings:
    $key_99a2 = { ca cd [2] ee c3 [2] c5 ef [2] eb cd [2] ff d6 [2] f0 cc [2] ee d1 [2] ec d0 [2] f7 d6 [2] eb d1 [2] f7 fe }

  condition:
    any of them
}