rule TTP_XOR_QUAD_CurrentVersionRun_9682 {
  strings:
    $key_9682 = { c5 ed [2] e1 e3 [2] ca cf [2] e4 ed [2] f0 f6 [2] ff ec [2] e1 f1 [2] e3 f0 [2] f8 f6 [2] e4 f1 [2] f8 de }

  condition:
    any of them
}