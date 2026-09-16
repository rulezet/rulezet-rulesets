rule TTP_XOR_QUAD_CurrentVersionRun_3282 {
  strings:
    $key_3282 = { 61 ed [2] 45 e3 [2] 6e cf [2] 40 ed [2] 54 f6 [2] 5b ec [2] 45 f1 [2] 47 f0 [2] 5c f6 [2] 40 f1 [2] 5c de }

  condition:
    any of them
}