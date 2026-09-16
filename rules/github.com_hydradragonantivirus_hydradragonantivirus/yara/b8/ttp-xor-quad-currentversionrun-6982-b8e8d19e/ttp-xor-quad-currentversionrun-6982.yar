rule TTP_XOR_QUAD_CurrentVersionRun_6982 {
  strings:
    $key_6982 = { 3a ed [2] 1e e3 [2] 35 cf [2] 1b ed [2] 0f f6 [2] 00 ec [2] 1e f1 [2] 1c f0 [2] 07 f6 [2] 1b f1 [2] 07 de }

  condition:
    any of them
}