rule TTP_XOR_QUAD_CurrentVersionRun_6c82 {
  strings:
    $key_6c82 = { 3f ed [2] 1b e3 [2] 30 cf [2] 1e ed [2] 0a f6 [2] 05 ec [2] 1b f1 [2] 19 f0 [2] 02 f6 [2] 1e f1 [2] 02 de }

  condition:
    any of them
}