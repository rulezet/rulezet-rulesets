rule TTP_XOR_QUAD_CurrentVersionRun_4d98 {
  strings:
    $key_4d98 = { 1e f7 [2] 3a f9 [2] 11 d5 [2] 3f f7 [2] 2b ec [2] 24 f6 [2] 3a eb [2] 38 ea [2] 23 ec [2] 3f eb [2] 23 c4 }

  condition:
    any of them
}