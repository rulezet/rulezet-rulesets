rule TTP_XOR_QUAD_CurrentVersionRun_9c82 {
  strings:
    $key_9c82 = { cf ed [2] eb e3 [2] c0 cf [2] ee ed [2] fa f6 [2] f5 ec [2] eb f1 [2] e9 f0 [2] f2 f6 [2] ee f1 [2] f2 de }

  condition:
    any of them
}