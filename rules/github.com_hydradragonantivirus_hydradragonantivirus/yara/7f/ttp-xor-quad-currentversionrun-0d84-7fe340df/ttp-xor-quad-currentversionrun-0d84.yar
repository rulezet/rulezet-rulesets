rule TTP_XOR_QUAD_CurrentVersionRun_0d84 {
  strings:
    $key_0d84 = { 5e eb [2] 7a e5 [2] 51 c9 [2] 7f eb [2] 6b f0 [2] 64 ea [2] 7a f7 [2] 78 f6 [2] 63 f0 [2] 7f f7 [2] 63 d8 }

  condition:
    any of them
}