rule TTP_XOR_QUAD_CurrentVersionRun_fa83 {
  strings:
    $key_fa83 = { a9 ec [2] 8d e2 [2] a6 ce [2] 88 ec [2] 9c f7 [2] 93 ed [2] 8d f0 [2] 8f f1 [2] 94 f7 [2] 88 f0 [2] 94 df }

  condition:
    any of them
}