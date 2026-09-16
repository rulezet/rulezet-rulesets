rule TTP_XOR_QUAD_CurrentVersionRun_3b83 {
  strings:
    $key_3b83 = { 68 ec [2] 4c e2 [2] 67 ce [2] 49 ec [2] 5d f7 [2] 52 ed [2] 4c f0 [2] 4e f1 [2] 55 f7 [2] 49 f0 [2] 55 df }

  condition:
    any of them
}