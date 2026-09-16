rule TTP_XOR_QUAD_CurrentVersionRun_803b {
  strings:
    $key_803b = { d3 54 [2] f7 5a [2] dc 76 [2] f2 54 [2] e6 4f [2] e9 55 [2] f7 48 [2] f5 49 [2] ee 4f [2] f2 48 [2] ee 67 }

  condition:
    any of them
}