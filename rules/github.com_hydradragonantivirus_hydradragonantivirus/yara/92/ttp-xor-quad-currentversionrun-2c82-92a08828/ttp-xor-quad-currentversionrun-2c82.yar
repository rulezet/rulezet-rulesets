rule TTP_XOR_QUAD_CurrentVersionRun_2c82 {
  strings:
    $key_2c82 = { 7f ed [2] 5b e3 [2] 70 cf [2] 5e ed [2] 4a f6 [2] 45 ec [2] 5b f1 [2] 59 f0 [2] 42 f6 [2] 5e f1 [2] 42 de }

  condition:
    any of them
}