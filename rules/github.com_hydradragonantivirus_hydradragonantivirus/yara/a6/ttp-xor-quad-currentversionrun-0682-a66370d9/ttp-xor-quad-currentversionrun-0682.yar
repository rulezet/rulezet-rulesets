rule TTP_XOR_QUAD_CurrentVersionRun_0682 {
  strings:
    $key_0682 = { 55 ed [2] 71 e3 [2] 5a cf [2] 74 ed [2] 60 f6 [2] 6f ec [2] 71 f1 [2] 73 f0 [2] 68 f6 [2] 74 f1 [2] 68 de }

  condition:
    any of them
}