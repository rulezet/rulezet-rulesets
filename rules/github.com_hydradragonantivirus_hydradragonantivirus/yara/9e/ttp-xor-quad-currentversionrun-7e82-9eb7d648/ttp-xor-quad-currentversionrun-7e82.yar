rule TTP_XOR_QUAD_CurrentVersionRun_7e82 {
  strings:
    $key_7e82 = { 2d ed [2] 09 e3 [2] 22 cf [2] 0c ed [2] 18 f6 [2] 17 ec [2] 09 f1 [2] 0b f0 [2] 10 f6 [2] 0c f1 [2] 10 de }

  condition:
    any of them
}