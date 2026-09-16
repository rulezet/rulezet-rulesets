rule TTP_XOR_QUAD_CurrentVersionRun_4f98 {
  strings:
    $key_4f98 = { 1c f7 [2] 38 f9 [2] 13 d5 [2] 3d f7 [2] 29 ec [2] 26 f6 [2] 38 eb [2] 3a ea [2] 21 ec [2] 3d eb [2] 21 c4 }

  condition:
    any of them
}