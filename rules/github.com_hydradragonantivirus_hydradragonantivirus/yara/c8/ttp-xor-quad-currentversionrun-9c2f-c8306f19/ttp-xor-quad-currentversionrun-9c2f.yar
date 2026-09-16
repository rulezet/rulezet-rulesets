rule TTP_XOR_QUAD_CurrentVersionRun_9c2f {
  strings:
    $key_9c2f = { cf 40 [2] eb 4e [2] c0 62 [2] ee 40 [2] fa 5b [2] f5 41 [2] eb 5c [2] e9 5d [2] f2 5b [2] ee 5c [2] f2 73 }

  condition:
    any of them
}