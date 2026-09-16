rule TTP_XOR_QUAD_CurrentVersionRun_5b83 {
  strings:
    $key_5b83 = { 08 ec [2] 2c e2 [2] 07 ce [2] 29 ec [2] 3d f7 [2] 32 ed [2] 2c f0 [2] 2e f1 [2] 35 f7 [2] 29 f0 [2] 35 df }

  condition:
    any of them
}