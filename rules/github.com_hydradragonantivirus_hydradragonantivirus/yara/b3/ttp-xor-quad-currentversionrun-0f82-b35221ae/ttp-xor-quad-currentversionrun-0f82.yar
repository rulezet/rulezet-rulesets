rule TTP_XOR_QUAD_CurrentVersionRun_0f82 {
  strings:
    $key_0f82 = { 5c ed [2] 78 e3 [2] 53 cf [2] 7d ed [2] 69 f6 [2] 66 ec [2] 78 f1 [2] 7a f0 [2] 61 f6 [2] 7d f1 [2] 61 de }

  condition:
    any of them
}