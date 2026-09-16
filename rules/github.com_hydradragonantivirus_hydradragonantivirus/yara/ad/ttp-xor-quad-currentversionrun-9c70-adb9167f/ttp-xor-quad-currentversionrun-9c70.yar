rule TTP_XOR_QUAD_CurrentVersionRun_9c70 {
  strings:
    $key_9c70 = { cf 1f [2] eb 11 [2] c0 3d [2] ee 1f [2] fa 04 [2] f5 1e [2] eb 03 [2] e9 02 [2] f2 04 [2] ee 03 [2] f2 2c }

  condition:
    any of them
}