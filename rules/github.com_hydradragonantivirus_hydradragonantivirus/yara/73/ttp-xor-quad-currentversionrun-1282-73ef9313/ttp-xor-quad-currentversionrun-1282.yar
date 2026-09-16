rule TTP_XOR_QUAD_CurrentVersionRun_1282 {
  strings:
    $key_1282 = { 41 ed [2] 65 e3 [2] 4e cf [2] 60 ed [2] 74 f6 [2] 7b ec [2] 65 f1 [2] 67 f0 [2] 7c f6 [2] 60 f1 [2] 7c de }

  condition:
    any of them
}