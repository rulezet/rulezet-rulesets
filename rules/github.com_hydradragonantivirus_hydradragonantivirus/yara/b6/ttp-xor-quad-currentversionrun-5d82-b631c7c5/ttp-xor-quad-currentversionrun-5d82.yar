rule TTP_XOR_QUAD_CurrentVersionRun_5d82 {
  strings:
    $key_5d82 = { 0e ed [2] 2a e3 [2] 01 cf [2] 2f ed [2] 3b f6 [2] 34 ec [2] 2a f1 [2] 28 f0 [2] 33 f6 [2] 2f f1 [2] 33 de }

  condition:
    any of them
}