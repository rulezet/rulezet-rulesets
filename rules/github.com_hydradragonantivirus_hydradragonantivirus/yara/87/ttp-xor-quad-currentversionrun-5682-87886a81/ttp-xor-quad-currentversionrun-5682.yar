rule TTP_XOR_QUAD_CurrentVersionRun_5682 {
  strings:
    $key_5682 = { 05 ed [2] 21 e3 [2] 0a cf [2] 24 ed [2] 30 f6 [2] 3f ec [2] 21 f1 [2] 23 f0 [2] 38 f6 [2] 24 f1 [2] 38 de }

  condition:
    any of them
}