rule TTP_XOR_QUAD_CurrentVersionRun_4982 {
  strings:
    $key_4982 = { 1a ed [2] 3e e3 [2] 15 cf [2] 3b ed [2] 2f f6 [2] 20 ec [2] 3e f1 [2] 3c f0 [2] 27 f6 [2] 3b f1 [2] 27 de }

  condition:
    any of them
}