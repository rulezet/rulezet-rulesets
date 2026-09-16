rule TTP_XOR_QUAD_CurrentVersionRun_9cfb {
  strings:
    $key_9cfb = { cf 94 [2] eb 9a [2] c0 b6 [2] ee 94 [2] fa 8f [2] f5 95 [2] eb 88 [2] e9 89 [2] f2 8f [2] ee 88 [2] f2 a7 }

  condition:
    any of them
}