rule TTP_XOR_QUAD_CurrentVersionRun_7a83 {
  strings:
    $key_7a83 = { 29 ec [2] 0d e2 [2] 26 ce [2] 08 ec [2] 1c f7 [2] 13 ed [2] 0d f0 [2] 0f f1 [2] 14 f7 [2] 08 f0 [2] 14 df }

  condition:
    any of them
}