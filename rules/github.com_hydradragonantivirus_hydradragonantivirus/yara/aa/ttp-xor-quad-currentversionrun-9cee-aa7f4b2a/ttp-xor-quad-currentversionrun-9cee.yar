rule TTP_XOR_QUAD_CurrentVersionRun_9cee {
  strings:
    $key_9cee = { cf 81 [2] eb 8f [2] c0 a3 [2] ee 81 [2] fa 9a [2] f5 80 [2] eb 9d [2] e9 9c [2] f2 9a [2] ee 9d [2] f2 b2 }

  condition:
    any of them
}