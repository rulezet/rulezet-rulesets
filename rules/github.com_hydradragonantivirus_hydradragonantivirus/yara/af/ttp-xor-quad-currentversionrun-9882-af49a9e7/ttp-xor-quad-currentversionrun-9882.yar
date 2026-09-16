rule TTP_XOR_QUAD_CurrentVersionRun_9882 {
  strings:
    $key_9882 = { cb ed [2] ef e3 [2] c4 cf [2] ea ed [2] fe f6 [2] f1 ec [2] ef f1 [2] ed f0 [2] f6 f6 [2] ea f1 [2] f6 de }

  condition:
    any of them
}