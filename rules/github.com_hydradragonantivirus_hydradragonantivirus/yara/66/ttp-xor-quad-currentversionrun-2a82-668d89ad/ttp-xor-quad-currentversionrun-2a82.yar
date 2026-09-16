rule TTP_XOR_QUAD_CurrentVersionRun_2a82 {
  strings:
    $key_2a82 = { 79 ed [2] 5d e3 [2] 76 cf [2] 58 ed [2] 4c f6 [2] 43 ec [2] 5d f1 [2] 5f f0 [2] 44 f6 [2] 58 f1 [2] 44 de }

  condition:
    any of them
}