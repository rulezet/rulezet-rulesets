rule TTP_XOR_QUAD_CurrentVersionRun_4282 {
  strings:
    $key_4282 = { 11 ed [2] 35 e3 [2] 1e cf [2] 30 ed [2] 24 f6 [2] 2b ec [2] 35 f1 [2] 37 f0 [2] 2c f6 [2] 30 f1 [2] 2c de }

  condition:
    any of them
}