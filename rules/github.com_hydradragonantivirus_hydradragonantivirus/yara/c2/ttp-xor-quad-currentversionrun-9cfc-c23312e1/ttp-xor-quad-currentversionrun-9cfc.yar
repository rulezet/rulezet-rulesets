rule TTP_XOR_QUAD_CurrentVersionRun_9cfc {
  strings:
    $key_9cfc = { cf 93 [2] eb 9d [2] c0 b1 [2] ee 93 [2] fa 88 [2] f5 92 [2] eb 8f [2] e9 8e [2] f2 88 [2] ee 8f [2] f2 a0 }

  condition:
    any of them
}