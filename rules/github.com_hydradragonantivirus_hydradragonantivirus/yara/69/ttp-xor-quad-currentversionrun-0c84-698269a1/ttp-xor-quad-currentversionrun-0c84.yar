rule TTP_XOR_QUAD_CurrentVersionRun_0c84 {
  strings:
    $key_0c84 = { 5f eb [2] 7b e5 [2] 50 c9 [2] 7e eb [2] 6a f0 [2] 65 ea [2] 7b f7 [2] 79 f6 [2] 62 f0 [2] 7e f7 [2] 62 d8 }

  condition:
    any of them
}