rule TTP_XOR_QUAD_CurrentVersionRun_2298 {
  strings:
    $key_2298 = { 71 f7 [2] 55 f9 [2] 7e d5 [2] 50 f7 [2] 44 ec [2] 4b f6 [2] 55 eb [2] 57 ea [2] 4c ec [2] 50 eb [2] 4c c4 }

  condition:
    any of them
}