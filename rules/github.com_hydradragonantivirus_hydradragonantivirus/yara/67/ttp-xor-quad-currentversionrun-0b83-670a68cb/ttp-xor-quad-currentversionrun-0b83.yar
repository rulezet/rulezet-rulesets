rule TTP_XOR_QUAD_CurrentVersionRun_0b83 {
  strings:
    $key_0b83 = { 58 ec [2] 7c e2 [2] 57 ce [2] 79 ec [2] 6d f7 [2] 62 ed [2] 7c f0 [2] 7e f1 [2] 65 f7 [2] 79 f0 [2] 65 df }

  condition:
    any of them
}