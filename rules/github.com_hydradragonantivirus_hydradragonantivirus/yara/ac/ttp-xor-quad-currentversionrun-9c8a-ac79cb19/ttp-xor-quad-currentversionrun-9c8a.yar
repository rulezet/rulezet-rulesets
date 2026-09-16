rule TTP_XOR_QUAD_CurrentVersionRun_9c8a {
  strings:
    $key_9c8a = { cf e5 [2] eb eb [2] c0 c7 [2] ee e5 [2] fa fe [2] f5 e4 [2] eb f9 [2] e9 f8 [2] f2 fe [2] ee f9 [2] f2 d6 }

  condition:
    any of them
}