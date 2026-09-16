rule TTP_XOR_QUAD_CurrentVersionRun_6f82 {
  strings:
    $key_6f82 = { 3c ed [2] 18 e3 [2] 33 cf [2] 1d ed [2] 09 f6 [2] 06 ec [2] 18 f1 [2] 1a f0 [2] 01 f6 [2] 1d f1 [2] 01 de }

  condition:
    any of them
}