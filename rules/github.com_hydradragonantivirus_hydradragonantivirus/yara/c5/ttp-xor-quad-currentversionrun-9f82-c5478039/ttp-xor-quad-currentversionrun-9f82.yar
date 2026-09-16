rule TTP_XOR_QUAD_CurrentVersionRun_9f82 {
  strings:
    $key_9f82 = { cc ed [2] e8 e3 [2] c3 cf [2] ed ed [2] f9 f6 [2] f6 ec [2] e8 f1 [2] ea f0 [2] f1 f6 [2] ed f1 [2] f1 de }

  condition:
    any of them
}