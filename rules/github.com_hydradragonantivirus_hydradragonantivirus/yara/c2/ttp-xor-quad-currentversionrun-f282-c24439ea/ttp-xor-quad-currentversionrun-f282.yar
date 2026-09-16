rule TTP_XOR_QUAD_CurrentVersionRun_f282 {
  strings:
    $key_f282 = { a1 ed [2] 85 e3 [2] ae cf [2] 80 ed [2] 94 f6 [2] 9b ec [2] 85 f1 [2] 87 f0 [2] 9c f6 [2] 80 f1 [2] 9c de }

  condition:
    any of them
}