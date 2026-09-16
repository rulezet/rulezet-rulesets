rule TTP_XOR_QUAD_CurrentVersionRun_1c83 {
  strings:
    $key_1c83 = { 4f ec [2] 6b e2 [2] 40 ce [2] 6e ec [2] 7a f7 [2] 75 ed [2] 6b f0 [2] 69 f1 [2] 72 f7 [2] 6e f0 [2] 72 df }

  condition:
    any of them
}