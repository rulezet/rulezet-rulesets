rule TTP_XOR_QUAD_CurrentVersionRun_9c8f {
  strings:
    $key_9c8f = { cf e0 [2] eb ee [2] c0 c2 [2] ee e0 [2] fa fb [2] f5 e1 [2] eb fc [2] e9 fd [2] f2 fb [2] ee fc [2] f2 d3 }

  condition:
    any of them
}