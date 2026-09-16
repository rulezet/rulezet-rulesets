rule TTP_XOR_QUAD_CurrentVersionRun_8182 {
  strings:
    $key_8182 = { d2 ed [2] f6 e3 [2] dd cf [2] f3 ed [2] e7 f6 [2] e8 ec [2] f6 f1 [2] f4 f0 [2] ef f6 [2] f3 f1 [2] ef de }

  condition:
    any of them
}