rule TTP_XOR_QUAD_CurrentVersionRun_1882 {
  strings:
    $key_1882 = { 4b ed [2] 6f e3 [2] 44 cf [2] 6a ed [2] 7e f6 [2] 71 ec [2] 6f f1 [2] 6d f0 [2] 76 f6 [2] 6a f1 [2] 76 de }

  condition:
    any of them
}