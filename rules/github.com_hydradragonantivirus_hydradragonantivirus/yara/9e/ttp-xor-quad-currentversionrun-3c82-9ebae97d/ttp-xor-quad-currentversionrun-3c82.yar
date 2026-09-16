rule TTP_XOR_QUAD_CurrentVersionRun_3c82 {
  strings:
    $key_3c82 = { 6f ed [2] 4b e3 [2] 60 cf [2] 4e ed [2] 5a f6 [2] 55 ec [2] 4b f1 [2] 49 f0 [2] 52 f6 [2] 4e f1 [2] 52 de }

  condition:
    any of them
}