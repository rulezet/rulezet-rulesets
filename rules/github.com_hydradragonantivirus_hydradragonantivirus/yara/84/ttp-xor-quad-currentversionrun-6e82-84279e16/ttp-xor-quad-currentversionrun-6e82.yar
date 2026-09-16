rule TTP_XOR_QUAD_CurrentVersionRun_6e82 {
  strings:
    $key_6e82 = { 3d ed [2] 19 e3 [2] 32 cf [2] 1c ed [2] 08 f6 [2] 07 ec [2] 19 f1 [2] 1b f0 [2] 00 f6 [2] 1c f1 [2] 00 de }

  condition:
    any of them
}