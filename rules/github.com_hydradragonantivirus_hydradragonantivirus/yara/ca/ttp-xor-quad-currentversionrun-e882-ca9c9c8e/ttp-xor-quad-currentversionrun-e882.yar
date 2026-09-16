rule TTP_XOR_QUAD_CurrentVersionRun_e882 {
  strings:
    $key_e882 = { bb ed [2] 9f e3 [2] b4 cf [2] 9a ed [2] 8e f6 [2] 81 ec [2] 9f f1 [2] 9d f0 [2] 86 f6 [2] 9a f1 [2] 86 de }

  condition:
    any of them
}