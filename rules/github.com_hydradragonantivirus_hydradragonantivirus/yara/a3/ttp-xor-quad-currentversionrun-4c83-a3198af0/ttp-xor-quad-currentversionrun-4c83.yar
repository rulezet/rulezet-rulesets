rule TTP_XOR_QUAD_CurrentVersionRun_4c83 {
  strings:
    $key_4c83 = { 1f ec [2] 3b e2 [2] 10 ce [2] 3e ec [2] 2a f7 [2] 25 ed [2] 3b f0 [2] 39 f1 [2] 22 f7 [2] 3e f0 [2] 22 df }

  condition:
    any of them
}