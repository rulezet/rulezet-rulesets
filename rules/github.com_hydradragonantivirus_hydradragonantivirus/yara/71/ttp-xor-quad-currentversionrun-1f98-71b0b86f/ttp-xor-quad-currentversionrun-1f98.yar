rule TTP_XOR_QUAD_CurrentVersionRun_1f98 {
  strings:
    $key_1f98 = { 4c f7 [2] 68 f9 [2] 43 d5 [2] 6d f7 [2] 79 ec [2] 76 f6 [2] 68 eb [2] 6a ea [2] 71 ec [2] 6d eb [2] 71 c4 }

  condition:
    any of them
}