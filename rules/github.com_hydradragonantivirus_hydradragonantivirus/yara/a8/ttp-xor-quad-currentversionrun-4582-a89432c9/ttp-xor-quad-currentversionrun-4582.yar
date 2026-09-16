rule TTP_XOR_QUAD_CurrentVersionRun_4582 {
  strings:
    $key_4582 = { 16 ed [2] 32 e3 [2] 19 cf [2] 37 ed [2] 23 f6 [2] 2c ec [2] 32 f1 [2] 30 f0 [2] 2b f6 [2] 37 f1 [2] 2b de }

  condition:
    any of them
}