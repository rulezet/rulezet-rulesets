rule TTP_XOR_QUAD_CurrentVersionRun_fe82 {
  strings:
    $key_fe82 = { ad ed [2] 89 e3 [2] a2 cf [2] 8c ed [2] 98 f6 [2] 97 ec [2] 89 f1 [2] 8b f0 [2] 90 f6 [2] 8c f1 [2] 90 de }

  condition:
    any of them
}