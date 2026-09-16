rule TTP_XOR_QUAD_CurrentVersionRun_9d8f {
  strings:
    $key_9d8f = { ce e0 [2] ea ee [2] c1 c2 [2] ef e0 [2] fb fb [2] f4 e1 [2] ea fc [2] e8 fd [2] f3 fb [2] ef fc [2] f3 d3 }

  condition:
    any of them
}