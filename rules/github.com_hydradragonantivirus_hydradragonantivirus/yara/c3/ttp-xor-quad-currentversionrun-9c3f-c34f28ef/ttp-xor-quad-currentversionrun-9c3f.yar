rule TTP_XOR_QUAD_CurrentVersionRun_9c3f {
  strings:
    $key_9c3f = { cf 50 [2] eb 5e [2] c0 72 [2] ee 50 [2] fa 4b [2] f5 51 [2] eb 4c [2] e9 4d [2] f2 4b [2] ee 4c [2] f2 63 }

  condition:
    any of them
}