rule TTP_XOR_QUAD_CurrentVersionRun_6c84 {
  strings:
    $key_6c84 = { 3f eb [2] 1b e5 [2] 30 c9 [2] 1e eb [2] 0a f0 [2] 05 ea [2] 1b f7 [2] 19 f6 [2] 02 f0 [2] 1e f7 [2] 02 d8 }

  condition:
    any of them
}