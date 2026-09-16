rule TTP_XOR_QUAD_CurrentVersionRun_1b82 {
  strings:
    $key_1b82 = { 48 ed [2] 6c e3 [2] 47 cf [2] 69 ed [2] 7d f6 [2] 72 ec [2] 6c f1 [2] 6e f0 [2] 75 f6 [2] 69 f1 [2] 75 de }

  condition:
    any of them
}