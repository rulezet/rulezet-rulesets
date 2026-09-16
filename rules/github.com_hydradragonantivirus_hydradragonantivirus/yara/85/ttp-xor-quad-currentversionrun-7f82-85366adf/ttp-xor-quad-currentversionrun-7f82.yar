rule TTP_XOR_QUAD_CurrentVersionRun_7f82 {
  strings:
    $key_7f82 = { 2c ed [2] 08 e3 [2] 23 cf [2] 0d ed [2] 19 f6 [2] 16 ec [2] 08 f1 [2] 0a f0 [2] 11 f6 [2] 0d f1 [2] 11 de }

  condition:
    any of them
}