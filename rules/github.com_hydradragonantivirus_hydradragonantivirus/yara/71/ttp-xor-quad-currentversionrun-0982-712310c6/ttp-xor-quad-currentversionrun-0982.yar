rule TTP_XOR_QUAD_CurrentVersionRun_0982 {
  strings:
    $key_0982 = { 5a ed [2] 7e e3 [2] 55 cf [2] 7b ed [2] 6f f6 [2] 60 ec [2] 7e f1 [2] 7c f0 [2] 67 f6 [2] 7b f1 [2] 67 de }

  condition:
    any of them
}