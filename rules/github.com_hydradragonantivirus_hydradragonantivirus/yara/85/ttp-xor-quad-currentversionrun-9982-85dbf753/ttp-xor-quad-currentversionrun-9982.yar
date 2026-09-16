rule TTP_XOR_QUAD_CurrentVersionRun_9982 {
  strings:
    $key_9982 = { ca ed [2] ee e3 [2] c5 cf [2] eb ed [2] ff f6 [2] f0 ec [2] ee f1 [2] ec f0 [2] f7 f6 [2] eb f1 [2] f7 de }

  condition:
    any of them
}