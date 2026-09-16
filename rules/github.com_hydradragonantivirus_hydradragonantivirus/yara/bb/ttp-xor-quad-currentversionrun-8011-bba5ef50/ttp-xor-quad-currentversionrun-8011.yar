rule TTP_XOR_QUAD_CurrentVersionRun_8011 {
  strings:
    $key_8011 = { d3 7e [2] f7 70 [2] dc 5c [2] f2 7e [2] e6 65 [2] e9 7f [2] f7 62 [2] f5 63 [2] ee 65 [2] f2 62 [2] ee 4d }

  condition:
    any of them
}