rule TTP_XOR_QUAD_CurrentVersionRun_5f82 {
  strings:
    $key_5f82 = { 0c ed [2] 28 e3 [2] 03 cf [2] 2d ed [2] 39 f6 [2] 36 ec [2] 28 f1 [2] 2a f0 [2] 31 f6 [2] 2d f1 [2] 31 de }

  condition:
    any of them
}