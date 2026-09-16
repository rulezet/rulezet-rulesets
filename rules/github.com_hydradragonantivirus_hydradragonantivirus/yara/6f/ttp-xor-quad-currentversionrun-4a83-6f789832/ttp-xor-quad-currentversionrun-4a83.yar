rule TTP_XOR_QUAD_CurrentVersionRun_4a83 {
  strings:
    $key_4a83 = { 19 ec [2] 3d e2 [2] 16 ce [2] 38 ec [2] 2c f7 [2] 23 ed [2] 3d f0 [2] 3f f1 [2] 24 f7 [2] 38 f0 [2] 24 df }

  condition:
    any of them
}