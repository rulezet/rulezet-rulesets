rule TTP_XOR_QUAD_CurrentVersionRun_4d82 {
  strings:
    $key_4d82 = { 1e ed [2] 3a e3 [2] 11 cf [2] 3f ed [2] 2b f6 [2] 24 ec [2] 3a f1 [2] 38 f0 [2] 23 f6 [2] 3f f1 [2] 23 de }

  condition:
    any of them
}