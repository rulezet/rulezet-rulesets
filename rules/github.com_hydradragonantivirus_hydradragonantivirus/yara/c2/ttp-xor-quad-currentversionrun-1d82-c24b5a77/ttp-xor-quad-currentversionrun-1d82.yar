rule TTP_XOR_QUAD_CurrentVersionRun_1d82 {
  strings:
    $key_1d82 = { 4e ed [2] 6a e3 [2] 41 cf [2] 6f ed [2] 7b f6 [2] 74 ec [2] 6a f1 [2] 68 f0 [2] 73 f6 [2] 6f f1 [2] 73 de }

  condition:
    any of them
}