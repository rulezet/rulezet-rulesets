rule TTP_XOR_QUAD_CurrentVersionRun_4d84 {
  strings:
    $key_4d84 = { 1e eb [2] 3a e5 [2] 11 c9 [2] 3f eb [2] 2b f0 [2] 24 ea [2] 3a f7 [2] 38 f6 [2] 23 f0 [2] 3f f7 [2] 23 d8 }

  condition:
    any of them
}