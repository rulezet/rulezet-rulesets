rule TTP_XOR_QUAD_CurrentVersionRun_9c0f {
  strings:
    $key_9c0f = { cf 60 [2] eb 6e [2] c0 42 [2] ee 60 [2] fa 7b [2] f5 61 [2] eb 7c [2] e9 7d [2] f2 7b [2] ee 7c [2] f2 53 }

  condition:
    any of them
}