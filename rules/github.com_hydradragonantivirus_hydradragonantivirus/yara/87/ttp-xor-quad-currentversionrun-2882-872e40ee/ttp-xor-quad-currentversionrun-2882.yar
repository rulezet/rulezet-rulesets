rule TTP_XOR_QUAD_CurrentVersionRun_2882 {
  strings:
    $key_2882 = { 7b ed [2] 5f e3 [2] 74 cf [2] 5a ed [2] 4e f6 [2] 41 ec [2] 5f f1 [2] 5d f0 [2] 46 f6 [2] 5a f1 [2] 46 de }

  condition:
    any of them
}