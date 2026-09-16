rule TTP_XOR_QUAD_CurrentVersionRun_5b82 {
  strings:
    $key_5b82 = { 08 ed [2] 2c e3 [2] 07 cf [2] 29 ed [2] 3d f6 [2] 32 ec [2] 2c f1 [2] 2e f0 [2] 35 f6 [2] 29 f1 [2] 35 de }

  condition:
    any of them
}