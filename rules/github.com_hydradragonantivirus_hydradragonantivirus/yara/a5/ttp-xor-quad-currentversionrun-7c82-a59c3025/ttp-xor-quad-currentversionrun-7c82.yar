rule TTP_XOR_QUAD_CurrentVersionRun_7c82 {
  strings:
    $key_7c82 = { 2f ed [2] 0b e3 [2] 20 cf [2] 0e ed [2] 1a f6 [2] 15 ec [2] 0b f1 [2] 09 f0 [2] 12 f6 [2] 0e f1 [2] 12 de }

  condition:
    any of them
}