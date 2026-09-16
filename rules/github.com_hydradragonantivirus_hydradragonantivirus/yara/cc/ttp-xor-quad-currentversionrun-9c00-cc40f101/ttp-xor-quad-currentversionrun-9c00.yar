rule TTP_XOR_QUAD_CurrentVersionRun_9c00 {
  strings:
    $key_9c00 = { cf 6f [2] eb 61 [2] c0 4d [2] ee 6f [2] fa 74 [2] f5 6e [2] eb 73 [2] e9 72 [2] f2 74 [2] ee 73 [2] f2 5c }

  condition:
    any of them
}