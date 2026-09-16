rule TTP_XOR_QUAD_CurrentVersionRun_9e82 {
  strings:
    $key_9e82 = { cd ed [2] e9 e3 [2] c2 cf [2] ec ed [2] f8 f6 [2] f7 ec [2] e9 f1 [2] eb f0 [2] f0 f6 [2] ec f1 [2] f0 de }

  condition:
    any of them
}