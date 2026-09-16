rule TTP_XOR_QUAD_CurrentVersionRun_9d82 {
  strings:
    $key_9d82 = { ce ed [2] ea e3 [2] c1 cf [2] ef ed [2] fb f6 [2] f4 ec [2] ea f1 [2] e8 f0 [2] f3 f6 [2] ef f1 [2] f3 de }

  condition:
    any of them
}