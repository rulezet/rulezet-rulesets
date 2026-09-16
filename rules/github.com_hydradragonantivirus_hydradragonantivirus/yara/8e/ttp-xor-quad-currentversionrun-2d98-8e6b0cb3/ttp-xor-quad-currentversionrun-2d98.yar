rule TTP_XOR_QUAD_CurrentVersionRun_2d98 {
  strings:
    $key_2d98 = { 7e f7 [2] 5a f9 [2] 71 d5 [2] 5f f7 [2] 4b ec [2] 44 f6 [2] 5a eb [2] 58 ea [2] 43 ec [2] 5f eb [2] 43 c4 }

  condition:
    any of them
}