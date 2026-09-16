rule TTP_XOR_QUAD_CurrentVersionRun_5a82 {
  strings:
    $key_5a82 = { 09 ed [2] 2d e3 [2] 06 cf [2] 28 ed [2] 3c f6 [2] 33 ec [2] 2d f1 [2] 2f f0 [2] 34 f6 [2] 28 f1 [2] 34 de }

  condition:
    any of them
}