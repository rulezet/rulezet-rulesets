rule TTP_XOR_QUAD_CurrentVersionRun_9cf0 {
  strings:
    $key_9cf0 = { cf 9f [2] eb 91 [2] c0 bd [2] ee 9f [2] fa 84 [2] f5 9e [2] eb 83 [2] e9 82 [2] f2 84 [2] ee 83 [2] f2 ac }

  condition:
    any of them
}