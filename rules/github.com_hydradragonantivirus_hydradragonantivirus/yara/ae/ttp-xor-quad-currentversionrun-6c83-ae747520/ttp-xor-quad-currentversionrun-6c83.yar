rule TTP_XOR_QUAD_CurrentVersionRun_6c83 {
  strings:
    $key_6c83 = { 3f ec [2] 1b e2 [2] 30 ce [2] 1e ec [2] 0a f7 [2] 05 ed [2] 1b f0 [2] 19 f1 [2] 02 f7 [2] 1e f0 [2] 02 df }

  condition:
    any of them
}