rule TTP_XOR_QUAD_CurrentVersionRun_9f8f {
  strings:
    $key_9f8f = { cc e0 [2] e8 ee [2] c3 c2 [2] ed e0 [2] f9 fb [2] f6 e1 [2] e8 fc [2] ea fd [2] f1 fb [2] ed fc [2] f1 d3 }

  condition:
    any of them
}