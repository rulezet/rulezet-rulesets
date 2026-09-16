rule TTP_XOR_QUAD_CurrentVersionRun_2982 {
  strings:
    $key_2982 = { 7a ed [2] 5e e3 [2] 75 cf [2] 5b ed [2] 4f f6 [2] 40 ec [2] 5e f1 [2] 5c f0 [2] 47 f6 [2] 5b f1 [2] 47 de }

  condition:
    any of them
}