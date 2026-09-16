rule TTP_XOR_QUAD_CurrentVersionRun_3e98 {
  strings:
    $key_3e98 = { 6d f7 [2] 49 f9 [2] 62 d5 [2] 4c f7 [2] 58 ec [2] 57 f6 [2] 49 eb [2] 4b ea [2] 50 ec [2] 4c eb [2] 50 c4 }

  condition:
    any of them
}