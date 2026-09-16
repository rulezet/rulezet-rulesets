rule TTP_XOR_QUAD_CurrentVersionRun_f682 {
  strings:
    $key_f682 = { a5 ed [2] 81 e3 [2] aa cf [2] 84 ed [2] 90 f6 [2] 9f ec [2] 81 f1 [2] 83 f0 [2] 98 f6 [2] 84 f1 [2] 98 de }

  condition:
    any of them
}