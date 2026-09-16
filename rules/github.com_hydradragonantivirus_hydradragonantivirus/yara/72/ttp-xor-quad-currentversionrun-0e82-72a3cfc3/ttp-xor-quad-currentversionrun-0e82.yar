rule TTP_XOR_QUAD_CurrentVersionRun_0e82 {
  strings:
    $key_0e82 = { 5d ed [2] 79 e3 [2] 52 cf [2] 7c ed [2] 68 f6 [2] 67 ec [2] 79 f1 [2] 7b f0 [2] 60 f6 [2] 7c f1 [2] 60 de }

  condition:
    any of them
}