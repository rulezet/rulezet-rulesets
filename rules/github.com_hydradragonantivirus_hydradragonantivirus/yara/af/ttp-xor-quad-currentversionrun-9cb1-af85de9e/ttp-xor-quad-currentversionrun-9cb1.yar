rule TTP_XOR_QUAD_CurrentVersionRun_9cb1 {
  strings:
    $key_9cb1 = { cf de [2] eb d0 [2] c0 fc [2] ee de [2] fa c5 [2] f5 df [2] eb c2 [2] e9 c3 [2] f2 c5 [2] ee c2 [2] f2 ed }

  condition:
    any of them
}