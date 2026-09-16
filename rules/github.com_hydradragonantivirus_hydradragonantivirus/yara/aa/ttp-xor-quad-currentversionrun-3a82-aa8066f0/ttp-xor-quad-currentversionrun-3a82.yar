rule TTP_XOR_QUAD_CurrentVersionRun_3a82 {
  strings:
    $key_3a82 = { 69 ed [2] 4d e3 [2] 66 cf [2] 48 ed [2] 5c f6 [2] 53 ec [2] 4d f1 [2] 4f f0 [2] 54 f6 [2] 48 f1 [2] 54 de }

  condition:
    any of them
}