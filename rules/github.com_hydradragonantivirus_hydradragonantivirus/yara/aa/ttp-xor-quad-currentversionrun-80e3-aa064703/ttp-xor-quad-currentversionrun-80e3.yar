rule TTP_XOR_QUAD_CurrentVersionRun_80e3 {
  strings:
    $key_80e3 = { d3 8c [2] f7 82 [2] dc ae [2] f2 8c [2] e6 97 [2] e9 8d [2] f7 90 [2] f5 91 [2] ee 97 [2] f2 90 [2] ee bf }

  condition:
    any of them
}