rule TTP_XOR_QUAD_CurrentVersionRun_1d98 {
  strings:
    $key_1d98 = { 4e f7 [2] 6a f9 [2] 41 d5 [2] 6f f7 [2] 7b ec [2] 74 f6 [2] 6a eb [2] 68 ea [2] 73 ec [2] 6f eb [2] 73 c4 }

  condition:
    any of them
}