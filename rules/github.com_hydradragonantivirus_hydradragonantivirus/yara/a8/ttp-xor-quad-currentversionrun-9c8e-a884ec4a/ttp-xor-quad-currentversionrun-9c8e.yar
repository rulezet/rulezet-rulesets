rule TTP_XOR_QUAD_CurrentVersionRun_9c8e {
  strings:
    $key_9c8e = { cf e1 [2] eb ef [2] c0 c3 [2] ee e1 [2] fa fa [2] f5 e0 [2] eb fd [2] e9 fc [2] f2 fa [2] ee fd [2] f2 d2 }

  condition:
    any of them
}