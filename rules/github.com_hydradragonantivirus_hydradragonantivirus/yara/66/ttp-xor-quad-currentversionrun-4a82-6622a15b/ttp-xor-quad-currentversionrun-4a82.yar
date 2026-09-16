rule TTP_XOR_QUAD_CurrentVersionRun_4a82 {
  strings:
    $key_4a82 = { 19 ed [2] 3d e3 [2] 16 cf [2] 38 ed [2] 2c f6 [2] 23 ec [2] 3d f1 [2] 3f f0 [2] 24 f6 [2] 38 f1 [2] 24 de }

  condition:
    any of them
}