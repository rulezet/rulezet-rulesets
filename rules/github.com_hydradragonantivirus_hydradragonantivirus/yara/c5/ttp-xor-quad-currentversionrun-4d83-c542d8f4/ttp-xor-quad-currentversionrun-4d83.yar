rule TTP_XOR_QUAD_CurrentVersionRun_4d83 {
  strings:
    $key_4d83 = { 1e ec [2] 3a e2 [2] 11 ce [2] 3f ec [2] 2b f7 [2] 24 ed [2] 3a f0 [2] 38 f1 [2] 23 f7 [2] 3f f0 [2] 23 df }

  condition:
    any of them
}