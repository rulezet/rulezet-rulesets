rule TTP_XOR_QUAD_CurrentVersionRun_9c60 {
  strings:
    $key_9c60 = { cf 0f [2] eb 01 [2] c0 2d [2] ee 0f [2] fa 14 [2] f5 0e [2] eb 13 [2] e9 12 [2] f2 14 [2] ee 13 [2] f2 3c }

  condition:
    any of them
}