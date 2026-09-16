rule TTP_XOR_QUAD_CurrentVersionRun_ec82 {
  strings:
    $key_ec82 = { bf ed [2] 9b e3 [2] b0 cf [2] 9e ed [2] 8a f6 [2] 85 ec [2] 9b f1 [2] 99 f0 [2] 82 f6 [2] 9e f1 [2] 82 de }

  condition:
    any of them
}