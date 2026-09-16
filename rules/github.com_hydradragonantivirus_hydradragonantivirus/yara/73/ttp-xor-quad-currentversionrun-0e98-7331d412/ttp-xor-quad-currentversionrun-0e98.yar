rule TTP_XOR_QUAD_CurrentVersionRun_0e98 {
  strings:
    $key_0e98 = { 5d f7 [2] 79 f9 [2] 52 d5 [2] 7c f7 [2] 68 ec [2] 67 f6 [2] 79 eb [2] 7b ea [2] 60 ec [2] 7c eb [2] 60 c4 }

  condition:
    any of them
}