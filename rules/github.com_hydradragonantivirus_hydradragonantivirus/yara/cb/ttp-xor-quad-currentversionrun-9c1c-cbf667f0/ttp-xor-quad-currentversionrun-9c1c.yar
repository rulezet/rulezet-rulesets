rule TTP_XOR_QUAD_CurrentVersionRun_9c1c {
  strings:
    $key_9c1c = { cf 73 [2] eb 7d [2] c0 51 [2] ee 73 [2] fa 68 [2] f5 72 [2] eb 6f [2] e9 6e [2] f2 68 [2] ee 6f [2] f2 40 }

  condition:
    any of them
}