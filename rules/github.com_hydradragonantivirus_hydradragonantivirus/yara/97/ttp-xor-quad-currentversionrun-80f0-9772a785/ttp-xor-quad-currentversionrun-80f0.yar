rule TTP_XOR_QUAD_CurrentVersionRun_80f0 {
  strings:
    $key_80f0 = { d3 9f [2] f7 91 [2] dc bd [2] f2 9f [2] e6 84 [2] e9 9e [2] f7 83 [2] f5 82 [2] ee 84 [2] f2 83 [2] ee ac }

  condition:
    any of them
}