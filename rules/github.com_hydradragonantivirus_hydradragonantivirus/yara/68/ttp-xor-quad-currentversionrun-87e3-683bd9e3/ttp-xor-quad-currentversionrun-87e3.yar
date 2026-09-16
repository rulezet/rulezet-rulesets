rule TTP_XOR_QUAD_CurrentVersionRun_87e3 {
  strings:
    $key_87e3 = { d4 8c [2] f0 82 [2] db ae [2] f5 8c [2] e1 97 [2] ee 8d [2] f0 90 [2] f2 91 [2] e9 97 [2] f5 90 [2] e9 bf }

  condition:
    any of them
}