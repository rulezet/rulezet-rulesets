rule TTP_XOR_QUAD_CurrentVersionRun_9c4f {
  strings:
    $key_9c4f = { cf 20 [2] eb 2e [2] c0 02 [2] ee 20 [2] fa 3b [2] f5 21 [2] eb 3c [2] e9 3d [2] f2 3b [2] ee 3c [2] f2 13 }

  condition:
    any of them
}