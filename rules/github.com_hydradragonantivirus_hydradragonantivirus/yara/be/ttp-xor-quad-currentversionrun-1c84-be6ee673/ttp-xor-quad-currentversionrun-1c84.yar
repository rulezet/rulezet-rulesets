rule TTP_XOR_QUAD_CurrentVersionRun_1c84 {
  strings:
    $key_1c84 = { 4f eb [2] 6b e5 [2] 40 c9 [2] 6e eb [2] 7a f0 [2] 75 ea [2] 6b f7 [2] 69 f6 [2] 72 f0 [2] 6e f7 [2] 72 d8 }

  condition:
    any of them
}