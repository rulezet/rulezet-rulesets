rule TTP_XOR_QUAD_CurrentVersionRun_2e82 {
  strings:
    $key_2e82 = { 7d ed [2] 59 e3 [2] 72 cf [2] 5c ed [2] 48 f6 [2] 47 ec [2] 59 f1 [2] 5b f0 [2] 40 f6 [2] 5c f1 [2] 40 de }

  condition:
    any of them
}